/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
//! Versioned, immutable record of an authorization decision.
//!
//! The [`AuthorizationDecision`] captured by [`crate::Authorizer`] keeps
//! everything needed to reconstruct and audit an authorization result after
//! the fact:
//!
//! * the policy that matched (or the absence of a matching policy),
//! * every check and policy that was evaluated and whether it succeeded,
//! * the trust sources each evaluation relied on,
//! * the checks that failed,
//! * the budget that was consumed and the budget that remains.

use std::time::Duration;

use crate::datalog::TrustedOrigins;
use crate::error::{FailedAuthorizerCheck, FailedBlockCheck, FailedCheck, MatchedPolicy};
use crate::format::schema;

/// version of the serialized [`AuthorizationDecision`] record
///
/// bumping this constant lets consumers reject records produced by an
/// unknown format
pub const AUTHORIZATION_RECORD_VERSION: u32 = 1;

/// origin marker used in trust sources to represent the authorizer itself
pub const AUTHORIZER_ORIGIN: u32 = u32::MAX;

/// runtime budget, either consumed or remaining at the time of a decision
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Budget {
    pub facts: u64,
    pub iterations: u64,
    pub time: Duration,
    pub steps: u64,
}

impl Budget {
    pub(crate) fn to_proto(self) -> schema::Budget {
        schema::Budget {
            max_facts: Some(self.facts),
            max_iterations: Some(self.iterations),
            max_time: Some(self.time.as_nanos() as u64),
            max_steps: Some(self.steps),
        }
    }

    pub(crate) fn from_proto(input: &schema::Budget) -> Self {
        Budget {
            facts: input.max_facts.unwrap_or(0),
            iterations: input.max_iterations.unwrap_or(0),
            time: Duration::from_nanos(input.max_time.unwrap_or(0)),
            steps: input.max_steps.unwrap_or(0),
        }
    }
}

/// kind of item that was evaluated
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvaluationKind {
    /// a check declared by the authorizer
    AuthorizerCheck,
    /// a check declared by a token block
    BlockCheck,
    /// an allow or deny policy
    Policy,
}

impl EvaluationKind {
    fn to_proto(self) -> i32 {
        match self {
            EvaluationKind::AuthorizerCheck => {
                schema::authorization_result::evaluation::Kind::AuthorizerCheck as i32
            }
            EvaluationKind::BlockCheck => {
                schema::authorization_result::evaluation::Kind::BlockCheck as i32
            }
            EvaluationKind::Policy => schema::authorization_result::evaluation::Kind::Policy as i32,
        }
    }

    fn from_proto(value: i32) -> Result<Self, crate::error::Format> {
        match value {
            value
                if value
                    == schema::authorization_result::evaluation::Kind::AuthorizerCheck as i32 =>
            {
                Ok(EvaluationKind::AuthorizerCheck)
            }
            value if value == schema::authorization_result::evaluation::Kind::BlockCheck as i32 => {
                Ok(EvaluationKind::BlockCheck)
            }
            value if value == schema::authorization_result::evaluation::Kind::Policy as i32 => {
                Ok(EvaluationKind::Policy)
            }
            _ => Err(crate::error::Format::DeserializationError(format!(
                "unknown authorization evaluation kind: {value}"
            ))),
        }
    }
}

/// one check or policy evaluation, with the trust sources that were used
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evaluation {
    pub kind: EvaluationKind,
    /// index of the check (inside its block or the authorizer) or of the policy
    pub item_id: u32,
    /// index of the block holding the check, when `kind` is `BlockCheck`
    pub block_id: Option<u32>,
    /// whether the check or policy matched
    pub success: bool,
    /// pretty-printed check or policy
    pub rule: String,
    /// trust sources this evaluation was allowed to use
    pub trusted_origins: TrustedOrigins,
}

impl Evaluation {
    pub(crate) fn to_proto(&self) -> schema::authorization_result::Evaluation {
        schema::authorization_result::Evaluation {
            kind: self.kind.to_proto(),
            item_id: self.item_id,
            block_id: self.block_id,
            success: self.success,
            rule: self.rule.clone(),
            trusted_origins: crate::token::authorizer::snapshot::authorizer_origin_to_proto_origin(
                self.trusted_origins.as_origin(),
            ),
        }
    }

    pub(crate) fn from_proto(
        input: &schema::authorization_result::Evaluation,
    ) -> Result<Self, crate::error::Format> {
        let origin = crate::token::authorizer::snapshot::proto_origin_to_authorizer_origin(
            &input.trusted_origins,
        )?;

        Ok(Evaluation {
            kind: EvaluationKind::from_proto(input.kind)?,
            item_id: input.item_id,
            block_id: input.block_id,
            success: input.success,
            rule: input.rule.clone(),
            trusted_origins: TrustedOrigins::from_origin(origin),
        })
    }
}

/// the immutable, versioned record of an authorization decision
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationDecision {
    /// format version of this record
    pub version: u32,
    /// true when an allow policy matched and every check succeeded
    pub allowed: bool,
    /// the policy that matched, if any
    pub matched_policy: Option<MatchedPolicy>,
    /// every check and policy that was evaluated, in evaluation order
    pub evaluations: Vec<Evaluation>,
    /// checks that failed validation
    pub failed_checks: Vec<FailedCheck>,
    /// budget left after the decision was computed
    pub remaining_budget: Budget,
    /// budget consumed up to the decision
    pub consumed_budget: Budget,
    /// trust sources that were available to the authorizer itself
    pub authorizer_trusted_origins: TrustedOrigins,
    /// Datalog steps taken when the decision was computed
    pub elapsed_steps: u64,
    /// engine iterations reached when the decision was computed
    pub iterations: u64,
    /// total execution time recorded when the decision was computed
    pub execution_time: Duration,
}

impl AuthorizationDecision {
    pub(crate) fn to_proto(&self) -> schema::AuthorizationResult {
        schema::AuthorizationResult {
            version: Some(self.version),
            allowed: self.allowed,
            matched_policy: self.matched_policy.as_ref().map(|policy| match policy {
                MatchedPolicy::Allow(policy_id) => schema::authorization_result::MatchedPolicy {
                    policy_id: *policy_id as u32,
                    kind: schema::authorization_result::matched_policy::Kind::Allow as i32,
                },
                MatchedPolicy::Deny(policy_id) => schema::authorization_result::MatchedPolicy {
                    policy_id: *policy_id as u32,
                    kind: schema::authorization_result::matched_policy::Kind::Deny as i32,
                },
            }),
            evaluations: self.evaluations.iter().map(Evaluation::to_proto).collect(),
            failed_checks: self
                .failed_checks
                .iter()
                .map(failed_check_to_proto)
                .collect(),
            remaining_budget: self.remaining_budget.to_proto(),
            consumed_budget: self.consumed_budget.to_proto(),
            authorizer_trusted_origins:
                crate::token::authorizer::snapshot::authorizer_origin_to_proto_origin(
                    self.authorizer_trusted_origins.as_origin(),
                ),
            elapsed_steps: self.elapsed_steps,
            iterations: self.iterations,
            execution_time: self.execution_time.as_nanos() as u64,
        }
    }

    pub(crate) fn from_proto(
        input: &schema::AuthorizationResult,
    ) -> Result<Self, crate::error::Format> {
        let version = input.version.unwrap_or(0);
        if version == 0 || version > AUTHORIZATION_RECORD_VERSION {
            return Err(crate::error::Format::DeserializationError(format!(
                "unsupported authorization record version: {version}"
            )));
        }

        let matched_policy = match &input.matched_policy {
            None => None,
            Some(schema::authorization_result::MatchedPolicy { policy_id, kind }) => {
                let allow = schema::authorization_result::matched_policy::Kind::Allow as i32;
                let deny = schema::authorization_result::matched_policy::Kind::Deny as i32;
                match *kind {
                    value if value == allow => Some(MatchedPolicy::Allow(*policy_id as usize)),
                    value if value == deny => Some(MatchedPolicy::Deny(*policy_id as usize)),
                    _ => {
                        return Err(crate::error::Format::DeserializationError(format!(
                            "unknown matched policy kind: {kind}"
                        )))
                    }
                }
            }
        };

        let failed_checks = input
            .failed_checks
            .iter()
            .map(failed_check_from_proto)
            .collect::<Result<Vec<_>, _>>()?;

        let evaluations = input
            .evaluations
            .iter()
            .map(Evaluation::from_proto)
            .collect::<Result<Vec<_>, _>>()?;

        let origin = crate::token::authorizer::snapshot::proto_origin_to_authorizer_origin(
            &input.authorizer_trusted_origins,
        )?;

        Ok(AuthorizationDecision {
            version,
            allowed: input.allowed,
            matched_policy,
            evaluations,
            failed_checks,
            remaining_budget: Budget::from_proto(&input.remaining_budget),
            consumed_budget: Budget::from_proto(&input.consumed_budget),
            authorizer_trusted_origins: TrustedOrigins::from_origin(origin),
            elapsed_steps: input.elapsed_steps,
            iterations: input.iterations,
            execution_time: Duration::from_nanos(input.execution_time),
        })
    }

    /// returns the checks that failed validation
    pub fn failed_checks(&self) -> &[FailedCheck] {
        &self.failed_checks
    }

    /// returns the policy that matched, if any
    pub fn matched_policy(&self) -> Option<&MatchedPolicy> {
        self.matched_policy.as_ref()
    }
}

pub(crate) fn failed_check_to_proto(check: &FailedCheck) -> schema::FailedCheck {
    match check {
        FailedCheck::Block(FailedBlockCheck {
            block_id,
            check_id,
            rule,
        }) => schema::FailedCheck {
            kind: schema::failed_check::Kind::Block as i32,
            block_id: Some(*block_id),
            check_id: *check_id,
            rule: rule.clone(),
        },
        FailedCheck::Authorizer(FailedAuthorizerCheck { check_id, rule }) => schema::FailedCheck {
            kind: schema::failed_check::Kind::Authorizer as i32,
            block_id: None,
            check_id: *check_id,
            rule: rule.clone(),
        },
    }
}

pub(crate) fn failed_check_from_proto(
    check: &schema::FailedCheck,
) -> Result<FailedCheck, crate::error::Format> {
    let block = schema::failed_check::Kind::Block as i32;
    let authorizer = schema::failed_check::Kind::Authorizer as i32;
    match check.kind {
        value if value == block => Ok(FailedCheck::Block(FailedBlockCheck {
            block_id: check.block_id.ok_or_else(|| {
                crate::error::Format::DeserializationError(
                    "block failed check is missing its block id".to_string(),
                )
            })?,
            check_id: check.check_id,
            rule: check.rule.clone(),
        })),
        value if value == authorizer => Ok(FailedCheck::Authorizer(FailedAuthorizerCheck {
            check_id: check.check_id,
            rule: check.rule.clone(),
        })),
        _ => Err(crate::error::Format::DeserializationError(format!(
            "unknown failed check kind: {}",
            check.kind
        ))),
    }
}
