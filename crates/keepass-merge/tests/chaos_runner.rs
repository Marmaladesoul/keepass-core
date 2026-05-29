#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::format_push_string,
    clippy::needless_pass_by_value,
    clippy::result_large_err
)]

//! Long-running chaos runner. Default-ignored so `cargo test` stays
//! cheap; run explicitly with:
//!
//! ```text
//! cargo test --test chaos_runner --release -- --ignored --nocapture
//! ```
//!
//! Each invocation iterates a configurable number of "scenarios"
//! seeded from `CHAOS_SEED` (env, default 0xC0FFEE). Per scenario:
//!
//! 1. Spin up two peers from a fresh `Sim`.
//! 2. Apply N (defaults to 30) random `Op`s split arbitrarily across
//!    the peers.
//! 3. Drive pairwise sync + assert convergence.
//! 4. On failure, print the captured op log so the scenario is
//!    bit-for-bit reproducible.
//!
//! Tune via env:
//! - `CHAOS_SCENARIOS` — outer iteration count (default 200 in
//!   release, 50 in debug).
//! - `CHAOS_OPS` — ops per scenario (default 30).
//! - `CHAOS_SEED` — base seed (default 0xC0FFEE).

mod common;

use common::sim::{ChaosConfig, Sim};

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// One chaos round: bootstrap shared state, then drive concurrent
/// edits on both peers against that shared substrate (the regime
/// where concurrent same-target edits are the rule, not the
/// exception), sync, check convergence.
fn run_chaos_round(
    seed: u64,
    bootstrap_ops: usize,
    divergence_ops: usize,
    rounds: usize,
) -> Result<(), String> {
    let cfg = ChaosConfig::default();
    let mut sim = Sim::new(2, seed);

    // Phase 1: shared substrate — apply bootstrap_ops on peer 0,
    // then sync to peer 1. After this both peers carry the same set
    // of entries / groups for the divergence phase to target.
    for _ in 0..bootstrap_ops {
        sim.apply_chaos_on(0, &cfg)
            .map_err(|e| format!("bootstrap apply: {e:?}"))?;
    }
    sim.sync_pairwise(0, 1)
        .map_err(|e| format!("bootstrap sync: {e:?}"))?;
    sim.assert_converged()
        .map_err(|d| format!("post-bootstrap divergence: {d}"))?;

    // Phase 2: alternating concurrent edits + sync. Each loop:
    //   - both peers apply N divergence ops (often targeting the
    //     shared substrate built in phase 1);
    //   - sync;
    //   - assert convergence.
    for round in 0..rounds {
        for _ in 0..divergence_ops {
            sim.apply_chaos_on(0, &cfg)
                .map_err(|e| format!("round {round} peer-0 apply: {e:?}"))?;
            sim.apply_chaos_on(1, &cfg)
                .map_err(|e| format!("round {round} peer-1 apply: {e:?}"))?;
        }
        sim.sync_pairwise(0, 1)
            .map_err(|e| format!("round {round} sync: {e:?}"))?;
        sim.assert_converged().map_err(|d| {
            let mut out = format!(
                "round {round} divergence: {d}\nop log ({}):\n",
                sim.op_log().len()
            );
            for (i, (peer, op)) in sim.op_log().iter().enumerate() {
                out.push_str(&format!("  {i}: peer={peer} op={op:?}\n"));
            }
            out
        })?;
    }
    Ok(())
}

#[test]
#[ignore = "long-running chaos sweep; opt in with --ignored"]
fn chaos_two_peer() {
    let base_seed = env_u64("CHAOS_SEED", 0x00C0_FFEE);
    let scenarios = env_u64(
        "CHAOS_SCENARIOS",
        if cfg!(debug_assertions) { 50 } else { 200 },
    );
    let bootstrap_ops = env_u64("CHAOS_BOOTSTRAP_OPS", 15) as usize;
    let divergence_ops = env_u64("CHAOS_OPS", 10) as usize;
    let rounds = env_u64("CHAOS_ROUNDS", 5) as usize;

    eprintln!(
        "chaos runner: {scenarios} scenarios, base seed {base_seed:#x}\n  bootstrap_ops={bootstrap_ops}, divergence_ops={divergence_ops}, rounds={rounds}"
    );

    let mut failures = 0usize;
    for s in 0..scenarios {
        let seed = base_seed.wrapping_add(s);
        if let Err(msg) = run_chaos_round(seed, bootstrap_ops, divergence_ops, rounds) {
            eprintln!("\n=== CHAOS FAILURE seed={seed:#x} ===\n{msg}\n=== END FAILURE ===\n");
            failures += 1;
        }
    }

    assert!(
        failures == 0,
        "{failures}/{scenarios} chaos scenarios failed; see stderr for replays"
    );
}
