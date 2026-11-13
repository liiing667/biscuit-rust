/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
use base64::prelude::*;
use prost::Message;
use std::{collections::HashMap, time::Duration};

use crate::{
    builder::{load_and_translate_block, BlockBuilder, Convert, Policy},
    datalog::{Origin, RunLimits, StepCounter, TrustedOrigins},
    error,
    format::{
        convert::{
            policy_to_proto_policy, proto_fact_to_token_fact, proto_policy_to_policy,
            proto_snapshot_block_to_token_block, token_block_to_proto_snapshot_block,
            token_fact_to_proto_fact,
        },
        schema::{self, GeneratedFacts},
    },
    token::{default_symbol_table, MAX_SCHEMA_VERSION, MIN_SCHEMA_VERSION},
};
use crate::token::public_keys::PublicKeyData;

impl super::Authorizer {
    pub fn from_snapshot(input: schema::AuthorizerSnapshot) -> Result<Self, error::Token> {
        let schema::AuthorizerSnapshot {
            limits,
            execution_time,
            world,
            elapsed_steps,
            authorization_result,
        } = input;

        let limits = RunLimits {
            max_facts: limits.max_facts,
            max_iterations: limits.max_iterations,
            max_time: Duration::from_nanos(limits.max_time),
            max_steps: limits.max_steps.unwrap_or(RunLimits::DEFAULT_STEPS),
        };

        let execution_time = Duration::from_nanos(execution_time);

        let version = world.version.unwrap_or(0);
        if !(MIN_SCHEMA_VERSION..=MAX_SCHEMA_VERSION).contains(&version) {
            return Err(error::Format::Version {
                minimum: crate::token::MIN_SCHEMA_VERSION,
                maximum: crate::token::MAX_SCHEMA_VERSION,
                actual: version,
            }
            .into());
        }

        let mut symbols = default_symbol_table();
        for symbol in world.symbols {
            symbols.insert(&symbol);
        }
        for public_key in world.public_keys {
            symbols.public_keys.insert(&PublicKeyData::from_proto(&public_key));
        }

        let authorizer_block = proto_snapshot_block_to_token_block(&world.authorizer_block)?;

        let authorizer_block_builder = BlockBuilder::convert_from(&authorizer_block, &symbols)?;
        let policies = world
            .authorizer_policies
            .iter()
            .map(|policy| proto_policy_to_policy(policy, &symbols, version))
            .collect::<Result<Vec<Policy>, error::Format>>()?;

        let mut authorizer = super::Authorizer::new();
        authorizer.symbols = symbols;
        authorizer.authorizer_block_builder = authorizer_block_builder;
        authorizer.policies = policies;
        authorizer.limits = limits;
        authorizer.execution_time =
            Some(execution_time).filter(|_| execution_time > Duration::default());

        let mut public_key_to_block_id: HashMap<usize, Vec<usize>> = HashMap::new();
        let mut blocks = Vec::new();
        for (i, block) in world.blocks.iter().enumerate() {
            let token_symbols = if block.external_key.is_none() {
                authorizer.symbols.clone()
            } else {
                let mut token_symbols = authorizer.symbols.clone();
                token_symbols.public_keys = authorizer.symbols.public_keys.clone();
                token_symbols
            };

            let mut block = proto_snapshot_block_to_token_block(block)?;

            if let Some(key) = block.external_key.as_ref() {
                public_key_to_block_id
                    .entry(authorizer.symbols.public_keys.insert(key) as usize)
                    .or_default()
                    .push(i);
            }

            load_and_translate_block(
                &mut block,
                i,
                &token_symbols,
                &mut authorizer.symbols,
                &mut public_key_to_block_id,
                &mut authorizer.world,
            )?;
            blocks.push(block);
        }

        authorizer.public_key_to_block_id = public_key_to_block_id;

        if !blocks.is_empty() {
            authorizer.token_origins = TrustedOrigins::from_scopes(
                &[crate::token::Scope::Previous],
                &TrustedOrigins::default(),
                blocks.len(),
                &authorizer.public_key_to_block_id,
            );
            authorizer.blocks = Some(blocks);
        }

        let mut authorizer_origin = Origin::default();
        authorizer_origin.insert(usize::MAX);

        let authorizer_scopes: Vec<crate::token::Scope> = authorizer
            .authorizer_block_builder
            .scopes
            .clone()
            .iter()
            .map(|s| s.convert(&mut authorizer.symbols))
            .collect();

        let authorizer_trusted_origins = TrustedOrigins::from_scopes(
            &authorizer_scopes,
            &TrustedOrigins::default(),
            usize::MAX,
            &authorizer.public_key_to_block_id,
        );
        for fact in &authorizer.authorizer_block_builder.facts {
            authorizer
                .world
                .facts
                .insert(&authorizer_origin, fact.convert(&mut authorizer.symbols));
        }

        for rule in &authorizer.authorizer_block_builder.rules {
            let rule = rule.convert(&mut authorizer.symbols);

            let rule_trusted_origins = TrustedOrigins::from_scopes(
                &rule.scopes,
                &authorizer_trusted_origins,
                usize::MAX,
                &authorizer.public_key_to_block_id,
            );

            authorizer
                .world
                .rules
                .insert(usize::MAX, &rule_trusted_origins, rule);
        }

        for GeneratedFacts { origins, facts } in world.generated_facts {
            let origin = proto_origin_to_authorizer_origin(&origins)?;

            for fact in &facts {
                let fact = proto_fact_to_token_fact(fact)?;
                //let fact = Fact::convert_from(&fact, &symbols)?.convert(&mut authorizer.symbols);
                authorizer.world.facts.insert(&origin, fact);
            }
        }

        authorizer.world.iterations = world.iterations;
        authorizer.steps = StepCounter::with_taken(elapsed_steps.unwrap_or(0));

        if let Some(authorization_result) = authorization_result {
            let decision =
                crate::token::authorizer::authorization::AuthorizationDecision::from_proto(
                    &authorization_result,
                )?;
            verify_authorization_snapshot(
                &authorizer,
                &decision,
                elapsed_steps.unwrap_or(0),
                world.iterations,
                execution_time.as_nanos() as u64,
            )?;
            authorizer.authorization = Some(decision);
        }

        Ok(authorizer)
    }

    pub fn from_raw_snapshot(input: &[u8]) -> Result<Self, error::Token> {
        let snapshot = schema::AuthorizerSnapshot::decode(input).map_err(|e| {
            error::Format::DeserializationError(format!("deserialization error: {e:?}"))
        })?;
        Self::from_snapshot(snapshot)
    }

    pub fn from_base64_snapshot(input: &str) -> Result<Self, error::Token> {
        let bytes = BASE64_URL_SAFE.decode(input)?;
        Self::from_raw_snapshot(&bytes)
    }

    pub fn snapshot(&self) -> Result<schema::AuthorizerSnapshot, error::Format> {
        let mut symbols = default_symbol_table();

        let authorizer_policies = self
            .policies
            .iter()
            .map(|policy| policy_to_proto_policy(policy, &mut symbols))
            .collect();

        let authorizer_block = self
            .authorizer_block_builder
            .clone()
            .build(symbols.clone());
        symbols.extend(&authorizer_block.symbols)?;
        symbols.public_keys.extend(&authorizer_block.public_keys)?;

        let authorizer_block = token_block_to_proto_snapshot_block(&authorizer_block);

        let blocks = match self.blocks.as_ref() {
            None => Vec::new(),
            Some(blocks) => blocks
                .iter()
                .map(|block| {
                    block
                        .translate(&self.symbols, &mut symbols)
                        .map(|block| token_block_to_proto_snapshot_block(&block))
                })
                .collect::<Result<Vec<_>, error::Format>>()?,
        };

        let generated_facts = self
            .world
            .facts
            .by_origin()
            .into_iter()
            .map(|(origin, facts)| {
                Ok(GeneratedFacts {
                    origins: authorizer_origin_to_proto_origin(origin),
                    facts: facts
                        .iter()
                        .map(|fact| {
                            Ok(token_fact_to_proto_fact(
                                &crate::builder::Fact::convert_from(fact, &self.symbols)?
                                    .convert(&mut symbols),
                            ))
                        })
                        .collect::<Result<Vec<_>, error::Format>>()?,
                })
            })
            .collect::<Result<Vec<GeneratedFacts>, error::Format>>()?;

        let world = schema::AuthorizerWorld {
            version: Some(MAX_SCHEMA_VERSION),
            symbols: symbols.strings(),
            public_keys: symbols
                .public_keys
                .into_inner()
                .into_iter()
                .map(|key| key.to_proto())
                .collect(),
            blocks,
            authorizer_block,
            authorizer_policies,
            generated_facts,
            iterations: self.world.iterations,
        };

        Ok(schema::AuthorizerSnapshot {
            world,
            execution_time: self.execution_time.unwrap_or_default().as_nanos() as u64,
            elapsed_steps: Some(self.elapsed_steps()),
            authorization_result: self
                .authorization
                .as_ref()
                .map(crate::token::authorizer::authorization::AuthorizationDecision::to_proto),
            limits: schema::RunLimits {
                max_facts: self.limits.max_facts,
                max_iterations: self.limits.max_iterations,
                max_time: self.limits.max_time.as_nanos() as u64,
                max_steps: Some(self.limits.max_steps),
            },
        })
    }

    pub fn to_raw_snapshot(&self) -> Result<Vec<u8>, error::Format> {
        let snapshot = self.snapshot()?;
        let mut bytes = Vec::new();
        snapshot.encode(&mut bytes).map_err(|e| {
            error::Format::SerializationError(format!("serialization error: {e:?}"))
        })?;
        Ok(bytes)
    }

    pub fn to_base64_snapshot(&self) -> Result<String, error::Format> {
        let snapshot_bytes = self.to_raw_snapshot()?;
        Ok(BASE64_URL_SAFE.encode(snapshot_bytes))
    }
}

pub(crate) fn authorizer_origin_to_proto_origin(origin: &Origin) -> Vec<schema::Origin> {
    origin
        .inner
        .iter()
        .map(|o| {
            if *o == usize::MAX {
                schema::Origin {
                    content: Some(schema::origin::Content::Authorizer(schema::Empty {})),
                }
            } else {
                schema::Origin {
                    content: Some(schema::origin::Content::Origin(*o as u32)),
                }
            }
        })
        .collect()
}

pub(crate) fn proto_origin_to_authorizer_origin(
    origins: &[schema::Origin],
) -> Result<Origin, error::Format> {
    let mut new_origin = Origin::default();

    for origin in origins {
        match origin.content {
            Some(schema::origin::Content::Authorizer(schema::Empty {})) => {
                new_origin.insert(usize::MAX)
            }
            Some(schema::origin::Content::Origin(o)) => new_origin.insert(o as usize),
            _ => {
                return Err(error::Format::DeserializationError(
                    "invalid origin".to_string(),
                ))
            }
        }
    }

    Ok(new_origin)
}

/// verifies that an authorization record embedded in a snapshot is consistent
/// with the restored authorizer state, so a tampered record cannot be loaded
/// as a valid decision
fn verify_authorization_snapshot(
    authorizer: &super::Authorizer,
    decision: &crate::token::authorizer::authorization::AuthorizationDecision,
    elapsed_steps: u64,
    iterations: u64,
    execution_time: u64,
) -> Result<(), error::Token> {
    use crate::token::authorizer::authorization::EvaluationKind;

    fn error(message: String) -> error::Token {
        error::Token::Format(error::Format::DeserializationError(format!(
            "invalid authorization snapshot: {message}"
        )))
    }

    if decision.version == 0
        || decision.version > crate::token::authorizer::AUTHORIZATION_RECORD_VERSION
    {
        return Err(error(format!(
            "unsupported record version {}",
            decision.version
        )));
    }

    if decision.elapsed_steps != elapsed_steps {
        return Err(error(format!(
            "decision elapsed_steps {} does not match snapshot elapsed_steps {elapsed_steps}",
            decision.elapsed_steps
        )));
    }

    if decision.iterations != iterations {
        return Err(error(format!(
            "decision iterations {} does not match snapshot iterations {iterations}",
            decision.iterations
        )));
    }

    if decision.execution_time.as_nanos() as u64 != execution_time {
        return Err(error(format!(
            "decision execution_time {} does not match snapshot execution_time {execution_time}",
            decision.execution_time.as_nanos()
        )));
    }

    // every recorded failed check must match a recorded failing evaluation
    for failed_check in &decision.failed_checks {
        let matches = decision.evaluations.iter().any(|evaluation| {
            !evaluation.success
                && evaluation.rule == failed_check_rule(failed_check)
                && match (failed_check, evaluation.kind) {
                    (error::FailedCheck::Authorizer(check), EvaluationKind::AuthorizerCheck) => {
                        evaluation.item_id == check.check_id && evaluation.block_id.is_none()
                    }
                    (error::FailedCheck::Block(check), EvaluationKind::BlockCheck) => {
                        evaluation.item_id == check.check_id
                            && evaluation.block_id == Some(check.block_id)
                    }
                    _ => false,
                }
        });

        if !matches {
            return Err(error(format!(
                "failed check {failed_check} has no matching failed evaluation"
            )));
        }
    }

    // every failing check evaluation must be listed in the failed checks
    for evaluation in &decision.evaluations {
        if evaluation.success {
            continue;
        }

        let matches = decision.failed_checks.iter().any(|failed_check| {
            match (&evaluation.kind, failed_check) {
                (EvaluationKind::AuthorizerCheck, error::FailedCheck::Authorizer(check)) => {
                    evaluation.item_id == check.check_id && evaluation.rule == check.rule
                }
                (EvaluationKind::BlockCheck, error::FailedCheck::Block(check)) => {
                    evaluation.item_id == check.check_id
                        && evaluation.block_id == Some(check.block_id)
                        && evaluation.rule == check.rule
                }
                _ => false,
            }
        });

        if !matches {
            return Err(error(format!(
                "failing evaluation {} is missing from failed checks",
                evaluation.rule
            )));
        }
    }

    // indices and rules must match the checks and policies carried by the
    // restored authorizer
    for evaluation in &decision.evaluations {
        // every evaluation must record the trust sources it relied on
        if evaluation.trusted_origins.origins().next().is_none() {
            return Err(error(format!(
                "evaluation {} carries no trust sources",
                evaluation.rule
            )));
        }

        match evaluation.kind {
            EvaluationKind::AuthorizerCheck => {
                let check = authorizer
                    .authorizer_block_builder
                    .checks
                    .get(evaluation.item_id as usize)
                    .ok_or_else(|| {
                        error(format!(
                            "invalid authorization snapshot: authorizer check {} does not exist",
                            evaluation.item_id
                        ))
                    })?;
                if check.to_string() != evaluation.rule {
                    return Err(error(format!(
                        "authorizer check {} rule was modified in the snapshot",
                        evaluation.item_id
                    )));
                }
            }
            EvaluationKind::BlockCheck => {
                let block_id = evaluation.block_id.ok_or_else(|| {
                    error(
                        "invalid authorization snapshot: block check is missing its block id"
                            .to_string(),
                    )
                })? as usize;
                let blocks = authorizer.blocks.as_ref().ok_or_else(|| {
                    error(
                        "invalid authorization snapshot: snapshot references token blocks that are absent".to_string(),
                    )
                })?;
                let block = blocks.get(block_id).ok_or_else(|| {
                    error(format!(
                        "invalid authorization snapshot: block {block_id} does not exist"
                    ))
                })?;
                let check = block.checks.get(evaluation.item_id as usize).ok_or_else(|| {
                    error(format!(
                        "invalid authorization snapshot: check {} in block {block_id} does not exist",
                        evaluation.item_id
                    ))
                })?;
                if authorizer.symbols.print_check(check) != evaluation.rule {
                    return Err(error(format!(
                        "check {} in block {block_id} was modified in the snapshot",
                        evaluation.item_id
                    )));
                }
            }
            EvaluationKind::Policy => {
                let policy = authorizer
                    .policies
                    .get(evaluation.item_id as usize)
                    .ok_or_else(|| {
                        error(format!(
                            "invalid authorization snapshot: policy {} does not exist",
                            evaluation.item_id
                        ))
                    })?;
                if policy.to_string() != evaluation.rule {
                    return Err(error(format!(
                        "policy {} was modified in the snapshot",
                        evaluation.item_id
                    )));
                }
            }
        }
    }

    // the recorded decision must agree with the matched policy and the result
    let matched_policy = match &decision.matched_policy {
        None => None,
        Some(policy) => Some(policy),
    };

    let expected_allowed = matches!(matched_policy, Some(error::MatchedPolicy::Allow(_)))
        && decision.failed_checks.is_empty();
    if expected_allowed != decision.allowed {
        return Err(error(
            "the allowed flag contradicts the matched policy and failed checks".to_string(),
        ));
    }

    if let Some(policy) = matched_policy {
        let policy_id = match policy {
            error::MatchedPolicy::Allow(id) | error::MatchedPolicy::Deny(id) => *id,
        };
        let evaluation = decision
            .evaluations
            .iter()
            .find(|evaluation| {
                evaluation.kind == EvaluationKind::Policy
                    && evaluation.item_id as usize == policy_id
            })
            .ok_or_else(|| {
                error(format!(
                    "invalid authorization snapshot: matched policy {policy_id} was not evaluated"
                ))
            })?;
        if !evaluation.success {
            return Err(error(format!(
                "matched policy {policy_id} is recorded as not matching"
            )));
        }
    }

    // consumed and remaining budgets must add up to the configured limits
    let budget_ok = decision.consumed_budget.steps + decision.remaining_budget.steps
        == authorizer.limits.max_steps
        && decision.consumed_budget.iterations + decision.remaining_budget.iterations
            == authorizer.limits.max_iterations
        && decision.consumed_budget.facts + decision.remaining_budget.facts
            == authorizer.limits.max_facts
        && decision.consumed_budget.time.as_nanos() + decision.remaining_budget.time.as_nanos()
            == authorizer.limits.max_time.as_nanos();
    if !budget_ok {
        return Err(error(
            "consumed and remaining budgets do not match the run limits".to_string(),
        ));
    }

    if decision.consumed_budget.steps != elapsed_steps
        || decision.consumed_budget.iterations != iterations
    {
        return Err(error(
            "consumed budget does not match the restored engine state".to_string(),
        ));
    }

    if decision.consumed_budget.facts != authorizer.world.facts.len() as u64 {
        return Err(error(
            "consumed fact budget does not match the restored fact set".to_string(),
        ));
    }

    Ok(())
}

fn failed_check_rule(check: &error::FailedCheck) -> &str {
    match check {
        error::FailedCheck::Block(check) => &check.rule,
        error::FailedCheck::Authorizer(check) => &check.rule,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use crate::{datalog::RunLimits, Algorithm, AuthorizerBuilder};
    use crate::{Authorizer, BiscuitBuilder, PrivateKey};
    use crate::token::public_keys::PublicKeyData;

    #[test]
    fn roundtrip_builder() {
        let secp_pubkey = PublicKeyData::from(&PrivateKey::new_with_algorithm(Algorithm::Secp256r1).public());
        let ed_pubkey = PublicKeyData::from(&PrivateKey::new_with_algorithm(Algorithm::Ed25519).public());
        let builder = AuthorizerBuilder::new()
            .set_limits(RunLimits {
                max_facts: 42,
                max_iterations: 42,
                max_time: Duration::from_secs(1),
                max_steps: 42,
            })
            .code_with_params(
                r#"
                fact(true);
                head($a) <- fact($a);
                check if head(true) trusting authority, {ed_pubkey}, {secp_pubkey};
                allow if head(true);
                deny if head(false);
        "#,
                HashMap::default(),
                HashMap::from([
                    ("ed_pubkey".to_string(), ed_pubkey),
                    ("secp_pubkey".to_string(), secp_pubkey),
                ]),
            )
            .unwrap();
        let snapshot = builder.snapshot().unwrap();

        let parsed = AuthorizerBuilder::from_snapshot(snapshot).unwrap();
        assert_eq!(parsed.dump_code(), builder.dump_code());
        assert_eq!(parsed.limits, builder.limits);
    }

    #[test]
    fn roundtrip_with_token() {
        let secp_pubkey = PublicKeyData::from(&PrivateKey::new_with_algorithm(Algorithm::Secp256r1).public());
        let ed_pubkey = PublicKeyData::from(&PrivateKey::new_with_algorithm(Algorithm::Ed25519).public());
        let builder = AuthorizerBuilder::new()
            .set_limits(RunLimits {
                max_facts: 42,
                max_iterations: 42,
                max_time: Duration::from_secs(1),
                max_steps: 42,
            })
            .code_with_params(
                r#"
                fact(true);
                head($a) <- fact($a);
                check if head(true) trusting authority, {ed_pubkey}, {secp_pubkey};
                allow if head(true);
                deny if head(false);
        "#,
                HashMap::default(),
                HashMap::from([
                    ("ed_pubkey".to_string(), ed_pubkey.clone()),
                    ("secp_pubkey".to_string(), secp_pubkey.clone()),
                ]),
            )
            .unwrap();
        let biscuit = BiscuitBuilder::new()
            .code_with_params(
                r#"
                bfact(true);
                bhead($a) <- fact($a);
                check if bhead(true) trusting authority, {ed_pubkey}, {secp_pubkey};
                "#,
                HashMap::default(),
                HashMap::from([
                    ("ed_pubkey".to_string(), ed_pubkey),
                    ("secp_pubkey".to_string(), secp_pubkey),
                ]),
            )
            .unwrap()
            .build(&PrivateKey::new())
            .unwrap();

        let authorizer_pre_run = builder.build(&biscuit).unwrap();

        let snapshot = authorizer_pre_run.snapshot().unwrap();

        let parsed = Authorizer::from_snapshot(snapshot).unwrap();
        assert_eq!(parsed.dump_code(), authorizer_pre_run.dump_code());
        assert_eq!(parsed.limits(), authorizer_pre_run.limits());

        let mut authorizer_post_run = authorizer_pre_run.clone();
        let _ = authorizer_post_run.run();

        let snapshot = authorizer_post_run.snapshot().unwrap();

        let parsed = Authorizer::from_snapshot(snapshot).unwrap();
        assert_eq!(parsed.dump_code(), authorizer_post_run.dump_code());
        assert_eq!(parsed.limits(), authorizer_post_run.limits());
        assert!(authorizer_post_run.elapsed_steps() > 0);
        assert_eq!(parsed.elapsed_steps(), authorizer_post_run.elapsed_steps());
    }

    #[test]
    fn roundtrip_without_token() {
        let builder = AuthorizerBuilder::new()
            .set_limits(RunLimits {
                max_facts: 42,
                max_iterations: 42,
                max_time: Duration::from_secs(1),
                max_steps: 42,
            })
            .code(
                r#"
                fact(true);
                head($a) <- fact($a);
                check if head(true);
                allow if head(true);
                deny if head(false);
        "#,
            )
            .unwrap();
        let authorizer = builder.build_unauthenticated().unwrap();
        let snapshot = authorizer.snapshot().unwrap();

        let parsed = Authorizer::from_snapshot(snapshot).unwrap();
        assert_eq!(parsed.dump_code(), authorizer.dump_code());
        assert_eq!(parsed.limits(), authorizer.limits());

        let mut authorizer_post_run = authorizer.clone();
        let _ = authorizer_post_run.run();
        let snapshot = authorizer_post_run.snapshot().unwrap();

        let parsed = Authorizer::from_snapshot(snapshot).unwrap();
        assert_eq!(parsed.dump_code(), authorizer_post_run.dump_code());
        assert_eq!(parsed.limits(), authorizer_post_run.limits());
    }

    #[test]
    fn roundtrip_with_eval_error() {
        let builder = AuthorizerBuilder::new()
            .set_limits(RunLimits {
                max_facts: 42,
                max_iterations: 42,
                max_time: Duration::from_secs(1),
                max_steps: 42,
            })
            .code(
                r#"
                fact(true);
                head($a) <- fact($a), $a.length();
                allow if head(true);
                deny if head(false);
        "#,
            )
            .unwrap();
        let authorizer = builder.build_unauthenticated().unwrap();
        let snapshot = authorizer.snapshot().unwrap();

        let parsed = Authorizer::from_snapshot(snapshot).unwrap();
        assert_eq!(parsed.dump_code(), authorizer.dump_code());
        assert_eq!(parsed.limits(), authorizer.limits());

        let mut authorizer_post_run = authorizer.clone();
        let _ = authorizer_post_run.run();
        let snapshot = authorizer_post_run.snapshot().unwrap();

        let parsed = Authorizer::from_snapshot(snapshot).unwrap();
        assert_eq!(parsed.dump_code(), authorizer_post_run.dump_code());
        assert_eq!(parsed.limits(), authorizer_post_run.limits());
    }

    #[test]
    fn restored_snapshot_enforces_step_limit() {
        let authorizer = AuthorizerBuilder::new()
            .code(
                r#"
                fact(true);
                check if fact(true);
                allow if fact(true);
            "#,
            )
            .unwrap()
            .build_unauthenticated()
            .unwrap();

        let mut evaluated = authorizer.clone();
        let _ = evaluated.run();
        let snapshot = evaluated.snapshot().unwrap();

        let limits = |max_steps| RunLimits {
            max_steps,
            max_time: Duration::from_secs(1),
            ..Default::default()
        };

        let mut parsed = Authorizer::from_snapshot(snapshot.clone()).unwrap();
        assert!(parsed.authorize_with_limits(limits(100)).is_ok());

        let mut parsed = Authorizer::from_snapshot(snapshot).unwrap();
        assert!(matches!(
            parsed.authorize_with_limits(limits(1)),
            Err(crate::error::Token::RunLimit(
                crate::error::RunLimit::TooManySteps
            ))
        ));
    }

    #[test]
    fn restored_snapshot_keeps_counting_steps() {
        let mut authorizer = AuthorizerBuilder::new()
            .code("a(1); a(2); a(3); allow if a(1);")
            .unwrap()
            .set_limits(RunLimits {
                max_time: Duration::from_secs(10),
                ..Default::default()
            })
            .build_unauthenticated()
            .unwrap();
        authorizer.authorize().unwrap();
        let snapshot = authorizer.snapshot().unwrap();

        let mut parsed = Authorizer::from_snapshot(snapshot).unwrap();
        let restored = parsed.elapsed_steps();
        assert_eq!(restored, authorizer.elapsed_steps());

        let res: Vec<(i64,)> = parsed.query("b($x) <- a($x)").unwrap();
        assert_eq!(res.len(), 3);
        assert_eq!(parsed.elapsed_steps(), restored + 3);

        parsed.limits.max_steps = parsed.elapsed_steps() + 2;
        let res: Result<Vec<(i64,)>, _> = parsed.query("b($x) <- a($x)");
        assert_eq!(
            res.unwrap_err(),
            crate::error::Token::RunLimit(crate::error::RunLimit::TooManySteps)
        );
    }
    #[test]
    fn authorization_decision_is_recorded() {
        let mut authorizer = AuthorizerBuilder::new()
            .code(
                r#"
                fact(true);
                head($a) <- fact($a);
                check if head(true);
                allow if head(true);
            "#,
            )
            .unwrap()
            .build_unauthenticated()
            .unwrap();

        assert!(authorizer.authorization().is_none());

        let policy_id = authorizer.authorize().unwrap();
        assert_eq!(policy_id, 0);

        let decision = authorizer
            .authorization()
            .expect("an authorization decision must be recorded");
        assert_eq!(
            decision.version,
            crate::token::authorizer::AUTHORIZATION_RECORD_VERSION
        );
        assert!(decision.allowed);
        assert_eq!(
            decision.matched_policy,
            Some(crate::error::MatchedPolicy::Allow(0))
        );
        assert!(decision.failed_checks.is_empty());
        assert!(decision
            .evaluations
            .iter()
            .all(|evaluation| evaluation.success));
        assert!(decision.evaluations.iter().any(|evaluation| matches!(
            evaluation.kind,
            crate::token::authorizer::EvaluationKind::AuthorizerCheck
        )));
        assert!(decision.evaluations.iter().any(|evaluation| matches!(
            evaluation.kind,
            crate::token::authorizer::EvaluationKind::Policy
        )));
        assert!(decision.authorizer_trusted_origins.trusts_authorizer());
    }

    #[test]
    fn authorization_decision_records_failed_checks_and_deny() {
        let mut denied = AuthorizerBuilder::new()
            .code(
                r#"
                check if false;
                deny if true;
            "#,
            )
            .unwrap()
            .build_unauthenticated()
            .unwrap();

        let error = denied.authorize().unwrap_err();
        match error {
            crate::error::Token::FailedLogic(crate::error::Logic::Unauthorized {
                policy: crate::error::MatchedPolicy::Deny(0),
                ..
            }) => {}
            other => panic!("expected a deny policy error, got {:?}", other),
        }

        let decision = denied.authorization().expect("denied decision is recorded");
        assert!(!decision.allowed);
        assert_eq!(
            decision.matched_policy,
            Some(crate::error::MatchedPolicy::Deny(0))
        );
        assert_eq!(decision.failed_checks.len(), 1);
        assert!(decision
            .evaluations
            .iter()
            .any(|evaluation| !evaluation.success
                && evaluation.kind == crate::token::authorizer::EvaluationKind::AuthorizerCheck));

        let mut no_policy = AuthorizerBuilder::new()
            .code("check if false;")
            .unwrap()
            .build_unauthenticated()
            .unwrap();
        let error = no_policy.authorize().unwrap_err();
        assert!(matches!(
            error,
            crate::error::Token::FailedLogic(crate::error::Logic::NoMatchingPolicy { .. })
        ));
        let decision = no_policy
            .authorization()
            .expect("no-policy decision is recorded");
        assert!(!decision.allowed);
        assert!(decision.matched_policy.is_none());
        assert_eq!(decision.failed_checks.len(), 1);
    }

    #[test]
    fn authorization_decision_roundtrips_through_snapshot() {
        let mut authorizer = AuthorizerBuilder::new()
            .code(
                r#"
                fact(true);
                check if fact(true);
                allow if fact(true);
            "#,
            )
            .unwrap()
            .build_unauthenticated()
            .unwrap();
        authorizer.authorize().unwrap();

        let snapshot = authorizer.snapshot().unwrap();
        assert!(snapshot.authorization_result.is_some());

        let restored = Authorizer::from_snapshot(snapshot).unwrap();
        let original = authorizer.authorization().unwrap();
        let parsed = restored
            .authorization()
            .expect("the decision survives deserialization");

        assert_eq!(parsed.allowed, original.allowed);
        assert_eq!(parsed.matched_policy, original.matched_policy);
        assert_eq!(parsed.failed_checks, original.failed_checks);
        assert_eq!(parsed.evaluations.len(), original.evaluations.len());
        assert_eq!(parsed.evaluations, original.evaluations);
        assert_eq!(parsed.remaining_budget, original.remaining_budget);
        assert_eq!(parsed.consumed_budget, original.consumed_budget);
        assert_eq!(
            parsed.authorizer_trusted_origins,
            original.authorizer_trusted_origins
        );
        assert_eq!(parsed.elapsed_steps, original.elapsed_steps);
        assert_eq!(parsed.iterations, original.iterations);
        assert_eq!(parsed.execution_time, original.execution_time);

        // raw and base64 snapshot formats carry the record as well
        let raw = authorizer.to_raw_snapshot().unwrap();
        let from_raw = Authorizer::from_raw_snapshot(&raw).unwrap();
        assert!(from_raw.authorization().is_some());

        let encoded = authorizer.to_base64_snapshot().unwrap();
        let from_base64 = Authorizer::from_base64_snapshot(&encoded).unwrap();
        assert!(from_base64.authorization().is_some());
    }

    #[test]
    fn authorization_decision_roundtrips_with_token() {
        let biscuit = BiscuitBuilder::new()
            .code(
                r#"
                bfact(true);
                check if bfact(true);
                "#,
            )
            .unwrap()
            .build(&PrivateKey::new())
            .unwrap();

        let mut authorizer = AuthorizerBuilder::new()
            .code("allow if true;")
            .unwrap()
            .build(&biscuit)
            .unwrap();
        authorizer.authorize().unwrap();

        let snapshot = authorizer.snapshot().unwrap();
        let restored = Authorizer::from_snapshot(snapshot).unwrap();

        let original = authorizer.authorization().unwrap();
        let parsed = restored.authorization().unwrap();
        assert_eq!(parsed.evaluations, original.evaluations);
        assert_eq!(parsed.failed_checks, original.failed_checks);
        assert!(parsed
            .evaluations
            .iter()
            .any(|evaluation| evaluation.kind
                == crate::token::authorizer::EvaluationKind::BlockCheck));
    }

    #[test]
    fn snapshot_rejects_tampered_authorization_record() {
        let mut authorizer = AuthorizerBuilder::new()
            .code(
                r#"
                check if false;
                allow if true;
            "#,
            )
            .unwrap()
            .build_unauthenticated()
            .unwrap();
        let _ = authorizer.authorize();

        let mut snapshot = authorizer.snapshot().unwrap();
        let record = snapshot.authorization_result.as_mut().unwrap();

        // flipping the decision flag must be detected
        record.allowed = !record.allowed;
        assert!(Authorizer::from_snapshot(snapshot.clone()).is_err());

        // tampering with the remaining budget must be detected
        let mut snapshot = authorizer.snapshot().unwrap();
        snapshot
            .authorization_result
            .as_mut()
            .unwrap()
            .remaining_budget
            .max_steps = Some(42);
        assert!(Authorizer::from_snapshot(snapshot).is_err());

        // an unknown record version must be rejected
        let mut snapshot = authorizer.snapshot().unwrap();
        snapshot.authorization_result.as_mut().unwrap().version = Some(999);
        assert!(Authorizer::from_snapshot(snapshot).is_err());

        // a failed check without a matching failing evaluation must be rejected
        let mut snapshot = authorizer.snapshot().unwrap();
        let record = snapshot.authorization_result.as_mut().unwrap();
        record.failed_checks.clear();
        assert!(Authorizer::from_snapshot(snapshot).is_err());
    }

    #[test]
    fn builder_rejects_snapshot_with_authorization_record() {
        let mut authorizer = AuthorizerBuilder::new()
            .code("allow if true;")
            .unwrap()
            .build_unauthenticated()
            .unwrap();
        authorizer.authorize().unwrap();
        let snapshot = authorizer.snapshot().unwrap();
        assert!(AuthorizerBuilder::from_snapshot(snapshot).is_err());
    }

    #[test]
    fn budgets_are_consistent() {
        let limits = RunLimits {
            max_facts: 42,
            max_iterations: 42,
            max_time: Duration::from_secs(10),
            max_steps: 42,
        };
        let mut authorizer = AuthorizerBuilder::new()
            .set_limits(limits.clone())
            .code("a(1); a(2); allow if true;")
            .unwrap()
            .build_unauthenticated()
            .unwrap();
        authorizer.authorize().unwrap();

        let decision = authorizer.authorization().unwrap();
        assert_eq!(
            decision.consumed_budget.steps + decision.remaining_budget.steps,
            limits.max_steps
        );
        assert_eq!(
            decision.consumed_budget.facts + decision.remaining_budget.facts,
            limits.max_facts
        );
        assert_eq!(
            decision.consumed_budget.iterations + decision.remaining_budget.iterations,
            limits.max_iterations
        );
        assert_eq!(
            decision.consumed_budget.time + decision.remaining_budget.time,
            limits.max_time
        );
        assert!(decision.consumed_budget.facts >= 2);
        assert_eq!(decision.elapsed_steps, decision.consumed_budget.steps);
    }

    #[test]
    fn trust_sources_are_recorded_per_evaluation() {
        let mut authorizer = AuthorizerBuilder::new()
            .code(
                r#"
                fact(true);
                check if fact(true);
                allow if fact(true);
            "#,
            )
            .unwrap()
            .build_unauthenticated()
            .unwrap();
        authorizer.authorize().unwrap();

        let decision = authorizer.authorization().unwrap();
        for evaluation in &decision.evaluations {
            assert!(evaluation.trusted_origins.trusts_authorizer());
            assert!(!evaluation
                .trusted_origins
                .origins()
                .collect::<Vec<_>>()
                .is_empty());
        }

        let snapshot = authorizer.snapshot().unwrap();
        let restored = Authorizer::from_snapshot(snapshot).unwrap();
        let parsed = restored.authorization().unwrap();
        for (before, after) in decision.evaluations.iter().zip(parsed.evaluations.iter()) {
            assert_eq!(
                before.trusted_origins.origins().collect::<Vec<_>>(),
                after.trusted_origins.origins().collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn snapshot_without_authorization_record_stays_loadable() {
        // snapshots produced before the authorization record existed carry no
        // `authorization_result` field and must still deserialize
        let authorizer = AuthorizerBuilder::new()
            .code("allow if true;")
            .unwrap()
            .build_unauthenticated()
            .unwrap();

        let mut snapshot = authorizer.snapshot().unwrap();
        assert!(snapshot.authorization_result.is_none());
        snapshot.authorization_result = None;

        let restored = Authorizer::from_snapshot(snapshot).unwrap();
        assert!(restored.authorization().is_none());
        assert_eq!(restored.dump_code(), authorizer.dump_code());
    }

    #[test]
    fn failed_authorization_keeps_its_error_and_record() {
        let mut authorizer = AuthorizerBuilder::new()
            .code(
                r#"
                check if false;
                allow if true;
            "#,
            )
            .unwrap()
            .build_unauthenticated()
            .unwrap();

        let first_error = authorizer.authorize().unwrap_err();

        // the recorded decision and the returned error describe the same checks
        let decision = authorizer.authorization().unwrap();
        assert!(!decision.allowed);
        assert_eq!(decision.failed_checks().len(), 1);

        let snapshot = authorizer.snapshot().unwrap();
        let restored = Authorizer::from_snapshot(snapshot).unwrap();
        let restored_decision = restored.authorization().unwrap();
        assert_eq!(restored_decision.failed_checks(), decision.failed_checks());

        // re-running the restored authorizer yields the same error
        let mut restored = restored;
        let second_error = restored.authorize().unwrap_err();
        assert_eq!(first_error, second_error);
    }

    #[test]
    fn tampered_trusted_origins_are_rejected() {
        let mut authorizer = AuthorizerBuilder::new()
            .code("allow if true;")
            .unwrap()
            .build_unauthenticated()
            .unwrap();
        authorizer.authorize().unwrap();

        let mut snapshot = authorizer.snapshot().unwrap();
        let record = snapshot.authorization_result.as_mut().unwrap();
        // drop the trust sources of the first evaluation
        record.evaluations[0].trusted_origins.clear();
        assert!(Authorizer::from_snapshot(snapshot).is_err());
    }
// end-to-end audit scenario, kept as a doc-like sanity check
#[test]
fn audit_scenario_end_to_end() {
    use crate::{Authorizer, AuthorizerBuilder, EvaluationKind, PrivateKey, BiscuitBuilder};

    let root = PrivateKey::new();
    let token = BiscuitBuilder::new()
        .code(r#"right("file1", "read"); check if right("file1", "read");"#)
        .unwrap()
        .build(&root)
        .unwrap();

    let mut authorizer = AuthorizerBuilder::new()
        .code(
            r#"
            allow if right("file1", "read");
            deny if true;
            "#,
        )
        .unwrap()
        .build(&token)
        .unwrap();

    let policy_index = authorizer.authorize().unwrap();
    assert_eq!(policy_index, 0);

    // serialize the immutable audit record
    let bytes = authorizer.to_raw_snapshot().unwrap();
    // a fresh process reconstructs the decision without re-running anything
    let restored = Authorizer::from_raw_snapshot(&bytes).unwrap();
    let decision = restored.authorization().unwrap();

    assert!(decision.allowed);
    assert_eq!(decision.version, crate::AUTHORIZATION_RECORD_VERSION);
    assert_eq!(decision.matched_policy(), Some(&crate::error::MatchedPolicy::Allow(0)));
    assert!(decision.failed_checks().is_empty());

    let kinds: Vec<_> = decision
        .evaluations
        .iter()
        .map(|evaluation| evaluation.kind)
        .collect();
    assert!(kinds.contains(&EvaluationKind::Policy));
    assert!(kinds.contains(&EvaluationKind::BlockCheck));

    // every evaluation remembers its trust sources
    for evaluation in &decision.evaluations {
        assert!(evaluation.trusted_origins.trusts_authorizer());
    }

    // budgets are fully accounted for
    let limits = restored.limits();
    assert_eq!(
        decision.remaining_budget.steps + decision.consumed_budget.steps,
        limits.max_steps
    );
}
}
