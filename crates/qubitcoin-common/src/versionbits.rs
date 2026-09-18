//! BIP9 "versionbits" soft-fork deployment state machine.
//!
//! Maps to: `src/versionbits.h`, `src/versionbits_impl.h` and
//! `src/versionbits.cpp` in Bitcoin Core.
//!
//! BIP9 defines a finite state machine that walks a deployment through
//! `DEFINED -> STARTED -> LOCKED_IN -> ACTIVE` (or `-> FAILED`), with all
//! blocks of a retarget period sharing one state. Transitions are evaluated
//! once per period and cached; in a reorg they can go backwards, which is why
//! the cache is keyed on a block index rather than a height.
//!
//! Differences from Core, all mechanical:
//!
//! * Core keys the cache on `const CBlockIndex*`, with `nullptr` standing for
//!   the parent of genesis. Here blocks live in an arena and are addressed by
//!   index, so the key is `Option<usize>` and `None` plays the role of
//!   `nullptr`. Arena indices must therefore be stable for the lifetime of a
//!   cache — call [`VersionBitsCache::clear`] if the arena is ever rebuilt.
//! * `AbstractThresholdConditionChecker` becomes the
//!   [`ThresholdConditionChecker`] trait, with the same protected hooks
//!   (`condition`, `begin_time`, `end_time`, `min_activation_height`,
//!   `period`, `threshold`) and the same three provided algorithms.

use std::cell::RefCell;
use std::collections::HashMap;

use qubitcoin_consensus::params::{
    Bip9Deployment, ConsensusParams, DeploymentPos, MAX_VERSION_BITS_DEPLOYMENTS,
};

use crate::chain::{compute_mtp, get_ancestor, BlockIndex};
use crate::chainparams::ChainParams;

/// What block version to use for new blocks (pre-versionbits).
///
/// Maps to: `VERSIONBITS_LAST_OLD_BLOCK_VERSION`.
pub const VERSIONBITS_LAST_OLD_BLOCK_VERSION: i32 = 4;
/// What bits to set in a block's version for versionbits blocks.
///
/// Maps to: `VERSIONBITS_TOP_BITS`.
pub const VERSIONBITS_TOP_BITS: i32 = 0x2000_0000;
/// Bitmask that determines whether versionbits is in use.
///
/// Maps to: `VERSIONBITS_TOP_MASK`.
pub const VERSIONBITS_TOP_MASK: i32 = 0xE000_0000u32 as i32;
/// Total bits available for versionbits (BIP323).
///
/// Maps to: `VERSIONBITS_NUM_BITS`.
pub const VERSIONBITS_NUM_BITS: usize = 5;

/// Per-period state cache for one deployment.
///
/// Keyed by the *parent* of the block being evaluated, so every key is either
/// `None` (the parent of genesis) or a block with `(height + 1) % period == 0`.
///
/// Maps to: `ThresholdConditionCache`.
pub type ThresholdConditionCache = HashMap<Option<usize>, ThresholdState>;

/// State of a BIP9 deployment as of a particular block.
///
/// Maps to: `ThresholdState`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ThresholdState {
    /// First state every soft fork starts in. Genesis is `DEFINED` by definition.
    Defined,
    /// Blocks past the start time: miners may signal.
    Started,
    /// Threshold signalling was reached; waiting out one more period (and
    /// `min_activation_height`) before the rules take effect.
    LockedIn,
    /// The rules are enforced. Terminal.
    Active,
    /// The timeout passed without lock-in. Terminal.
    Failed,
}

impl ThresholdState {
    /// Lowercase name, as reported by `getdeploymentinfo`.
    ///
    /// Maps to: `StateName()`.
    pub fn name(self) -> &'static str {
        match self {
            ThresholdState::Defined => "defined",
            ThresholdState::Started => "started",
            ThresholdState::LockedIn => "locked_in",
            ThresholdState::Active => "active",
            ThresholdState::Failed => "failed",
        }
    }
}

/// Numerical status of an in-progress BIP9 soft fork.
///
/// Maps to: `BIP9Stats`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bip9Stats {
    /// Length in blocks of the signalling period.
    pub period: u32,
    /// Blocks that must signal within a period for lock-in.
    pub threshold: u32,
    /// Blocks elapsed since the beginning of the current period.
    pub elapsed: u32,
    /// Blocks that signalled since the beginning of the current period.
    pub count: u32,
    /// False once too few blocks remain in the period to still reach threshold.
    pub possible: bool,
}

/// Detailed status of an enabled BIP9 deployment.
///
/// Maps to: `BIP9Info`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Bip9Info {
    /// Height at which `current_state` started.
    pub since: i32,
    /// Name of the current state.
    pub current_state: &'static str,
    /// Name of the state the next block will be in.
    pub next_state: &'static str,
    /// Signalling statistics, where signalling is applicable.
    pub stats: Option<Bip9Stats>,
    /// Which blocks of the current period signalled; empty when not applicable.
    pub signalling_blocks: Vec<bool>,
    /// Height at which the deployment is (or will be) active, if known.
    pub active_since: Option<i32>,
}

/// One deployment's entry in the `getblocktemplate` rules lists.
///
/// Maps to: `BIP9GBTStatus::Info` plus the name from `VersionBitsDeploymentInfo`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GbtDeploymentInfo {
    /// Deployment name, e.g. `"testdummy"`.
    pub name: &'static str,
    /// Signalling bit position.
    pub bit: i32,
    /// `1 << bit`.
    pub mask: u32,
    /// Whether GBT clients may ignore the rule (the `!` prefix convention).
    pub gbt_optional_rule: bool,
}

/// Deployments grouped by state, for `getblocktemplate`.
///
/// Maps to: `BIP9GBTStatus`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Bip9GbtStatus {
    /// Deployments in `STARTED`.
    pub signalling: Vec<GbtDeploymentInfo>,
    /// Deployments in `LOCKED_IN`.
    pub locked_in: Vec<GbtDeploymentInfo>,
    /// Deployments in `ACTIVE`.
    pub active: Vec<GbtDeploymentInfo>,
}

/// Static per-deployment metadata.
///
/// Maps to: `VersionBitsDeploymentInfo` in `src/deploymentinfo.cpp`.
pub fn deployment_info(pos: DeploymentPos) -> GbtDeploymentInfoStatic {
    match pos {
        DeploymentPos::TestDummy => GbtDeploymentInfoStatic {
            name: "testdummy",
            gbt_optional_rule: true,
        },
    }
}

/// Name and GBT rule flag for a deployment. See [`deployment_info`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GbtDeploymentInfoStatic {
    /// Deployment name.
    pub name: &'static str,
    /// Whether GBT clients may ignore the rule.
    pub gbt_optional_rule: bool,
}

// ---------------------------------------------------------------------------
// The threshold state machine
// ---------------------------------------------------------------------------

/// BIP9-style threshold logic, with caching of per-period results.
///
/// Maps to: `AbstractThresholdConditionChecker`.
pub trait ThresholdConditionChecker {
    /// Does the block at `idx` signal for this deployment?
    fn condition(&self, arena: &[BlockIndex], idx: usize) -> bool;
    /// Median-time-past at which signalling may begin.
    fn begin_time(&self) -> i64;
    /// Median-time-past at which the attempt expires.
    fn end_time(&self) -> i64;
    /// Height before which activation is held back even after lock-in.
    fn min_activation_height(&self) -> i32 {
        0
    }
    /// Signalling period length, in blocks.
    fn period(&self) -> i32;
    /// Signalling blocks required within a period.
    fn threshold(&self) -> i32;

    /// State of the block whose parent is `prev`, applying any transition.
    ///
    /// Caches the state of the first block of each period.
    ///
    /// Maps to: `AbstractThresholdConditionChecker::GetStateFor`.
    fn get_state_for(
        &self,
        arena: &[BlockIndex],
        prev: Option<usize>,
        cache: &mut ThresholdConditionCache,
    ) -> ThresholdState {
        let n_period = self.period();
        let n_threshold = self.threshold();
        let min_activation_height = self.min_activation_height();
        let n_time_start = self.begin_time();
        let n_time_timeout = self.end_time();

        // Check if this deployment is always active.
        if n_time_start == Bip9Deployment::ALWAYS_ACTIVE {
            return ThresholdState::Active;
        }
        // Check if this deployment is never active.
        if n_time_start == Bip9Deployment::NEVER_ACTIVE {
            return ThresholdState::Failed;
        }

        // A block's state is always the same as that of the first block of its
        // period, so compute it from a `prev` whose height is a multiple of
        // period minus one.
        let mut prev = match prev {
            Some(p) => {
                let height = arena[p].height;
                get_ancestor(arena, p, height - ((height + 1) % n_period))
            }
            None => None,
        };

        // Walk backwards in steps of `period` to find a `prev` we know about.
        let mut to_compute: Vec<usize> = Vec::new();
        while !cache.contains_key(&prev) {
            let Some(p) = prev else {
                // The genesis block is by definition defined.
                cache.insert(None, ThresholdState::Defined);
                break;
            };
            if compute_mtp(arena, p) < n_time_start {
                // Optimization: every earlier block is before the start time.
                cache.insert(Some(p), ThresholdState::Defined);
                break;
            }
            to_compute.push(p);
            let height = arena[p].height;
            prev = get_ancestor(arena, p, height - n_period);
        }

        // At this point cache[prev] is known.
        let mut state = *cache
            .get(&prev)
            .expect("versionbits: cache entry must exist after backwards walk");

        // Now walk forward and compute the state of the descendants.
        while let Some(p) = to_compute.pop() {
            let mut state_next = state;
            match state {
                ThresholdState::Defined => {
                    if compute_mtp(arena, p) >= n_time_start {
                        state_next = ThresholdState::Started;
                    }
                }
                ThresholdState::Started => {
                    // Count signalling blocks over the whole period.
                    let mut count_idx = Some(p);
                    let mut count = 0i32;
                    for _ in 0..n_period {
                        let Some(ci) = count_idx else { break };
                        if self.condition(arena, ci) {
                            count += 1;
                        }
                        count_idx = arena[ci].prev;
                    }
                    if count >= n_threshold {
                        state_next = ThresholdState::LockedIn;
                    } else if compute_mtp(arena, p) >= n_time_timeout {
                        state_next = ThresholdState::Failed;
                    }
                }
                ThresholdState::LockedIn => {
                    // Progresses to ACTIVE once the activation height is reached.
                    if arena[p].height + 1 >= min_activation_height {
                        state_next = ThresholdState::Active;
                    }
                }
                // Terminal states.
                ThresholdState::Failed | ThresholdState::Active => {}
            }
            state = state_next;
            cache.insert(Some(p), state);
        }

        state
    }

    /// Signalling statistics for the period containing `idx`.
    ///
    /// When `signalling_blocks` is given it is resized to the number of blocks
    /// so far in the period and filled in, oldest first.
    ///
    /// Maps to: `AbstractThresholdConditionChecker::GetStateStatisticsFor`.
    fn get_state_statistics_for(
        &self,
        arena: &[BlockIndex],
        idx: Option<usize>,
        mut signalling_blocks: Option<&mut Vec<bool>>,
    ) -> Bip9Stats {
        let mut stats = Bip9Stats {
            period: self.period() as u32,
            threshold: self.threshold() as u32,
            ..Default::default()
        };

        let Some(idx) = idx else { return stats };

        // How many blocks are in the current period so far.
        let mut blocks_in_period = 1 + (arena[idx].height % self.period());

        if let Some(sb) = signalling_blocks.as_deref_mut() {
            sb.clear();
            sb.resize(blocks_in_period as usize, false);
        }

        let mut elapsed = 0u32;
        let mut count = 0u32;
        let mut current = Some(idx);
        loop {
            elapsed += 1;
            blocks_in_period -= 1;
            let Some(ci) = current else { break };
            if self.condition(arena, ci) {
                count += 1;
                if let Some(sb) = signalling_blocks.as_deref_mut() {
                    sb[blocks_in_period as usize] = true;
                }
            }
            current = arena[ci].prev;
            if blocks_in_period <= 0 {
                break;
            }
        }

        stats.elapsed = elapsed;
        stats.count = count;
        stats.possible = (stats.period - stats.threshold) >= (stats.elapsed - count);
        stats
    }

    /// Height since which the current state has held, for the block after `prev`.
    ///
    /// Maps to: `AbstractThresholdConditionChecker::GetStateSinceHeightFor`.
    fn get_state_since_height_for(
        &self,
        arena: &[BlockIndex],
        prev: Option<usize>,
        cache: &mut ThresholdConditionCache,
    ) -> i32 {
        let start_time = self.begin_time();
        if start_time == Bip9Deployment::ALWAYS_ACTIVE || start_time == Bip9Deployment::NEVER_ACTIVE
        {
            return 0;
        }

        let initial_state = self.get_state_for(arena, prev, cache);

        // BIP9 on DEFINED: "The genesis block is by definition in this state."
        if initial_state == ThresholdState::Defined {
            return 0;
        }

        let n_period = self.period();

        let Some(p) = prev else { return 0 };
        let height = arena[p].height;
        let mut prev = get_ancestor(arena, p, height - ((height + 1) % n_period))
            .expect("versionbits: period-aligned ancestor must exist");

        let mut previous_period_parent = get_ancestor(arena, prev, arena[prev].height - n_period);

        while let Some(ppp) = previous_period_parent {
            if self.get_state_for(arena, Some(ppp), cache) != initial_state {
                break;
            }
            prev = ppp;
            previous_period_parent = get_ancestor(arena, prev, arena[prev].height - n_period);
        }

        // Adjust: `prev` is the parent of the first block in that state.
        arena[prev].height + 1
    }
}

/// Threshold checker driven by a [`Bip9Deployment`] from the chain params.
///
/// Maps to: `VersionBitsConditionChecker`.
pub struct VersionBitsConditionChecker {
    dep: Bip9Deployment,
}

impl VersionBitsConditionChecker {
    /// Checker for one deployment's parameters.
    pub fn new(dep: Bip9Deployment) -> Self {
        Self { dep }
    }

    /// Checker for `pos` as configured on this network.
    pub fn for_deployment(params: &ConsensusParams, pos: DeploymentPos) -> Self {
        Self::new(params.deployments[pos.index()])
    }

    /// `1 << bit`, the version bit this deployment signals with.
    pub fn mask(&self) -> u32 {
        1u32 << self.dep.bit
    }

    /// Whether a raw block version signals for this deployment.
    pub fn condition_version(&self, n_version: i32) -> bool {
        (n_version & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS
            && (n_version & self.mask() as i32) != 0
    }
}

impl ThresholdConditionChecker for VersionBitsConditionChecker {
    fn condition(&self, arena: &[BlockIndex], idx: usize) -> bool {
        self.condition_version(arena[idx].version)
    }
    fn begin_time(&self) -> i64 {
        self.dep.start_time
    }
    fn end_time(&self) -> i64 {
        self.dep.timeout
    }
    fn min_activation_height(&self) -> i32 {
        self.dep.min_activation_height
    }
    fn period(&self) -> i32 {
        self.dep.period as i32
    }
    fn threshold(&self) -> i32 {
        self.dep.threshold as i32
    }
}

/// Determine what `nVersion` a new block on top of `prev` should use.
///
/// Free function so the warning checker can reuse it while the cache is
/// already borrowed.
///
/// Maps to: the file-local `ComputeBlockVersion()` in `src/versionbits.cpp`.
pub fn compute_block_version(
    arena: &[BlockIndex],
    prev: Option<usize>,
    params: &ConsensusParams,
    caches: &mut [ThresholdConditionCache; MAX_VERSION_BITS_DEPLOYMENTS],
) -> i32 {
    let mut n_version = VERSIONBITS_TOP_BITS;

    for pos in DeploymentPos::ALL {
        let checker = VersionBitsConditionChecker::for_deployment(params, pos);
        let state = checker.get_state_for(arena, prev, &mut caches[pos.index()]);
        if state == ThresholdState::LockedIn || state == ThresholdState::Started {
            n_version |= checker.mask() as i32;
        }
    }

    n_version
}

/// Threshold checker that fires when unknown version bits are being used on
/// the network, which is how the node warns about an unrecognised soft fork.
///
/// Maps to: the anonymous-namespace `WarningBitsConditionChecker`.
struct WarningBitsConditionChecker<'a> {
    params: &'a ConsensusParams,
    caches: RefCell<&'a mut [ThresholdConditionCache; MAX_VERSION_BITS_DEPLOYMENTS]>,
    bit: usize,
    period: i32,
    threshold: i32,
}

impl<'a> WarningBitsConditionChecker<'a> {
    fn new(
        chainparams: &'a ChainParams,
        caches: &'a mut [ThresholdConditionCache; MAX_VERSION_BITS_DEPLOYMENTS],
        bit: usize,
    ) -> Self {
        let mut period = 2016;
        let mut threshold = 1815; // 90% threshold used in BIP341.
        if chainparams.is_test_chain {
            period = chainparams.consensus.difficulty_adjustment_interval() as i32;
            threshold = period * 3 / 4; // 75% for test nets per BIP9's suggestion.
        }
        Self {
            params: &chainparams.consensus,
            caches: RefCell::new(caches),
            bit,
            period,
            threshold,
        }
    }
}

impl ThresholdConditionChecker for WarningBitsConditionChecker<'_> {
    fn begin_time(&self) -> i64 {
        0
    }
    fn end_time(&self) -> i64 {
        i64::MAX
    }
    fn period(&self) -> i32 {
        self.period
    }
    fn threshold(&self) -> i32 {
        self.threshold
    }
    fn condition(&self, arena: &[BlockIndex], idx: usize) -> bool {
        let block = &arena[idx];
        if block.height < self.params.min_bip9_warning_height {
            return false;
        }
        if (block.version & VERSIONBITS_TOP_MASK) != VERSIONBITS_TOP_BITS {
            return false;
        }
        if ((block.version >> self.bit) & 1) == 0 {
            return false;
        }
        // Only warn about bits that aren't already explained by a deployment
        // we know about.
        let mut caches = self.caches.borrow_mut();
        let expected = compute_block_version(arena, block.prev, self.params, &mut caches);
        ((expected >> self.bit) & 1) == 0
    }
}

/// Per-period BIP9 state caches: one per implemented deployment, plus one per
/// BIP323 bit for unknown-activation warnings.
///
/// Maps to: `VersionBitsCache`.
///
/// Arena indices are used as cache keys, so the cache is only valid while the
/// arena it was populated from stays index-stable. Rebuilding the arena
/// requires a [`clear`](VersionBitsCache::clear).
#[derive(Default)]
pub struct VersionBitsCache {
    caches: [ThresholdConditionCache; MAX_VERSION_BITS_DEPLOYMENTS],
    warning_caches: [ThresholdConditionCache; VERSIONBITS_NUM_BITS],
}

impl VersionBitsCache {
    /// Empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Detailed status of `pos` as of the block at `block_index`.
    ///
    /// Maps to: `VersionBitsCache::Info`.
    pub fn info(
        &mut self,
        arena: &[BlockIndex],
        block_index: usize,
        params: &ConsensusParams,
        pos: DeploymentPos,
    ) -> Bip9Info {
        let checker = VersionBitsConditionChecker::for_deployment(params, pos);
        let cache = &mut self.caches[pos.index()];
        let prev = arena[block_index].prev;

        let current_state = checker.get_state_for(arena, prev, cache);
        let next_state = checker.get_state_for(arena, Some(block_index), cache);
        let since = checker.get_state_since_height_for(arena, prev, cache);

        let mut result = Bip9Info {
            since,
            current_state: current_state.name(),
            next_state: next_state.name(),
            stats: None,
            signalling_blocks: Vec::new(),
            active_since: None,
        };

        let has_signal =
            current_state == ThresholdState::Started || current_state == ThresholdState::LockedIn;
        if has_signal {
            let mut signalling = Vec::new();
            let mut stats =
                checker.get_state_statistics_for(arena, Some(block_index), Some(&mut signalling));
            if current_state == ThresholdState::LockedIn {
                stats.threshold = 0;
                stats.possible = false;
            }
            result.stats = Some(stats);
            result.signalling_blocks = signalling;
        }

        if current_state == ThresholdState::Active {
            result.active_since = Some(result.since);
        } else if next_state == ThresholdState::Active {
            result.active_since = Some(arena[block_index].height + 1);
        }

        result
    }

    /// Deployments grouped by state, for `getblocktemplate`.
    ///
    /// Maps to: `VersionBitsCache::GBTStatus`.
    pub fn gbt_status(
        &mut self,
        arena: &[BlockIndex],
        block_index: usize,
        params: &ConsensusParams,
    ) -> Bip9GbtStatus {
        let mut result = Bip9GbtStatus::default();
        for pos in DeploymentPos::ALL {
            let checker = VersionBitsConditionChecker::for_deployment(params, pos);
            let state =
                checker.get_state_for(arena, Some(block_index), &mut self.caches[pos.index()]);
            let static_info = deployment_info(pos);
            let info = GbtDeploymentInfo {
                name: static_info.name,
                bit: params.deployments[pos.index()].bit,
                mask: checker.mask(),
                gbt_optional_rule: static_info.gbt_optional_rule,
            };
            match state {
                // Not exposed to GBT.
                ThresholdState::Defined | ThresholdState::Failed => {}
                ThresholdState::Started => result.signalling.push(info),
                ThresholdState::LockedIn => result.locked_in.push(info),
                ThresholdState::Active => result.active.push(info),
            }
        }
        result
    }

    /// Is `pos` active for the block *after* `prev`?
    ///
    /// Maps to: `VersionBitsCache::IsActiveAfter`.
    pub fn is_active_after(
        &mut self,
        arena: &[BlockIndex],
        prev: Option<usize>,
        params: &ConsensusParams,
        pos: DeploymentPos,
    ) -> bool {
        VersionBitsConditionChecker::for_deployment(params, pos).get_state_for(
            arena,
            prev,
            &mut self.caches[pos.index()],
        ) == ThresholdState::Active
    }

    /// `nVersion` for a new block built on `prev`.
    ///
    /// Maps to: `VersionBitsCache::ComputeBlockVersion`.
    pub fn compute_block_version(
        &mut self,
        arena: &[BlockIndex],
        prev: Option<usize>,
        params: &ConsensusParams,
    ) -> i32 {
        compute_block_version(arena, prev, params, &mut self.caches)
    }

    /// Bits that appear to carry an unknown deployment, with `true` meaning
    /// `ACTIVE` rather than merely `LOCKED_IN`.
    ///
    /// Maps to: `VersionBitsCache::CheckUnknownActivations`.
    pub fn check_unknown_activations(
        &mut self,
        arena: &[BlockIndex],
        index: Option<usize>,
        chainparams: &ChainParams,
    ) -> Vec<(usize, bool)> {
        let VersionBitsCache {
            caches,
            warning_caches,
        } = self;
        let mut result = Vec::new();
        for bit in 0..VERSIONBITS_NUM_BITS {
            let checker = WarningBitsConditionChecker::new(chainparams, caches, bit);
            let state = checker.get_state_for(arena, index, &mut warning_caches[bit]);
            if state == ThresholdState::Active || state == ThresholdState::LockedIn {
                result.push((bit, state == ThresholdState::Active));
            }
        }
        result
    }

    /// Drop all cached state. Required after the block-index arena is rebuilt.
    ///
    /// Maps to: `VersionBitsCache::Clear`.
    pub fn clear(&mut self) {
        for cache in self.caches.iter_mut() {
            cache.clear();
        }
        for cache in self.warning_caches.iter_mut() {
            cache.clear();
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::get_skip_height;

    /// Build a linear chain of `n` blocks. `version_at(height)` supplies each
    /// block's version and `time_at(height)` its timestamp. Skip pointers are
    /// filled in so ancestor lookups stay O(log n).
    fn build_arena(
        n: i32,
        version_at: impl Fn(i32) -> i32,
        time_at: impl Fn(i32) -> u32,
    ) -> Vec<BlockIndex> {
        let mut arena: Vec<BlockIndex> = Vec::with_capacity(n as usize);
        for height in 0..n {
            let mut index = BlockIndex::new();
            index.version = version_at(height);
            index.time = time_at(height);
            index.time_max = index.time;
            index.bits = 0x207f_ffff;
            index.height = height;
            index.prev = if height == 0 {
                None
            } else {
                Some((height - 1) as usize)
            };
            arena.push(index);
            // Maps to: CBlockIndex::BuildSkip().
            if let Some(prev) = arena[height as usize].prev {
                arena[height as usize].skip = get_ancestor(&arena, prev, get_skip_height(height));
            }
        }
        arena
    }

    /// Deployment used by most tests: bit 28, period 10, threshold 8.
    fn dep(start_time: i64, timeout: i64, min_activation_height: i32) -> Bip9Deployment {
        Bip9Deployment {
            bit: 28,
            start_time,
            timeout,
            min_activation_height,
            period: 10,
            threshold: 8,
        }
    }

    const SIGNAL: i32 = VERSIONBITS_TOP_BITS | (1 << 28);
    const NO_SIGNAL: i32 = VERSIONBITS_TOP_BITS;

    /// MTP is the median of the last 11 blocks, so with a 100s spacing the MTP
    /// of block h is `base + (h - 5) * 100` once h >= 10.
    fn time_at(height: i32) -> u32 {
        (1_000_000 + height as i64 * 100) as u32
    }

    fn state_at(arena: &[BlockIndex], prev: Option<usize>, d: Bip9Deployment) -> ThresholdState {
        let checker = VersionBitsConditionChecker::new(d);
        let mut cache = ThresholdConditionCache::new();
        checker.get_state_for(arena, prev, &mut cache)
    }

    #[test]
    fn test_always_active_is_active_from_genesis() {
        let arena = build_arena(5, |_| NO_SIGNAL, time_at);
        let d = dep(Bip9Deployment::ALWAYS_ACTIVE, Bip9Deployment::NO_TIMEOUT, 0);
        assert_eq!(state_at(&arena, None, d), ThresholdState::Active);
        assert_eq!(state_at(&arena, Some(4), d), ThresholdState::Active);
    }

    #[test]
    fn test_never_active_is_failed_from_genesis() {
        let arena = build_arena(5, |_| SIGNAL, time_at);
        let d = dep(Bip9Deployment::NEVER_ACTIVE, Bip9Deployment::NO_TIMEOUT, 0);
        assert_eq!(state_at(&arena, None, d), ThresholdState::Failed);
        assert_eq!(state_at(&arena, Some(4), d), ThresholdState::Failed);
    }

    #[test]
    fn test_full_activation_cycle() {
        // 60 blocks, all signalling, start time in the past.
        let arena = build_arena(60, |_| SIGNAL, time_at);
        let d = dep(0, Bip9Deployment::NO_TIMEOUT, 0);
        let checker = VersionBitsConditionChecker::new(d);
        let mut cache = ThresholdConditionCache::new();

        // Genesis's parent is DEFINED...
        assert_eq!(
            checker.get_state_for(&arena, None, &mut cache),
            ThresholdState::Defined
        );
        // ...and so is everything in the first period (state is evaluated on
        // the period boundary, and the boundary before it is genesis).
        assert_eq!(
            checker.get_state_for(&arena, Some(8), &mut cache),
            ThresholdState::Defined
        );
        // Block 10 is the first of period 1: with MTP past the start time the
        // period turns STARTED.
        assert_eq!(
            checker.get_state_for(&arena, Some(9), &mut cache),
            ThresholdState::Started
        );
        // Period 1 signalled 10/10 >= 8, so period 2 locks in.
        assert_eq!(
            checker.get_state_for(&arena, Some(19), &mut cache),
            ThresholdState::LockedIn
        );
        // And period 3 activates.
        assert_eq!(
            checker.get_state_for(&arena, Some(29), &mut cache),
            ThresholdState::Active
        );
        // ACTIVE is terminal.
        assert_eq!(
            checker.get_state_for(&arena, Some(59), &mut cache),
            ThresholdState::Active
        );
    }

    #[test]
    fn test_insufficient_signalling_never_locks_in() {
        // 7 of every 10 blocks signal; threshold is 8.
        let arena = build_arena(60, |h| if h % 10 < 7 { SIGNAL } else { NO_SIGNAL }, time_at);
        let d = dep(0, Bip9Deployment::NO_TIMEOUT, 0);
        assert_eq!(state_at(&arena, Some(19), d), ThresholdState::Started);
        assert_eq!(state_at(&arena, Some(59), d), ThresholdState::Started);
    }

    #[test]
    fn test_timeout_fails() {
        // Nobody signals and the timeout is early, so the deployment fails.
        let arena = build_arena(60, |_| NO_SIGNAL, time_at);
        let d = dep(0, 1_000_500, 0);
        assert_eq!(state_at(&arena, Some(19), d), ThresholdState::Failed);
        assert_eq!(state_at(&arena, Some(59), d), ThresholdState::Failed);
    }

    #[test]
    fn test_lockin_wins_over_timeout_in_same_period() {
        // Everyone signals, and the timeout lands inside the STARTED period.
        // BIP9 checks the threshold first, so it locks in rather than failing.
        let arena = build_arena(60, |_| SIGNAL, time_at);
        let d = dep(0, 1_000_500, 0);
        assert_eq!(state_at(&arena, Some(19), d), ThresholdState::LockedIn);
        assert_eq!(state_at(&arena, Some(29), d), ThresholdState::Active);
    }

    #[test]
    fn test_min_activation_height_delays_activation() {
        let arena = build_arena(80, |_| SIGNAL, time_at);
        // Lock-in happens at height 20; hold activation until height 50.
        let d = dep(0, Bip9Deployment::NO_TIMEOUT, 50);
        assert_eq!(state_at(&arena, Some(19), d), ThresholdState::LockedIn);
        // Still locked in at the period that would otherwise have activated.
        assert_eq!(state_at(&arena, Some(29), d), ThresholdState::LockedIn);
        assert_eq!(state_at(&arena, Some(39), d), ThresholdState::LockedIn);
        // Height 50 is a period boundary, so period starting at 50 is ACTIVE.
        assert_eq!(state_at(&arena, Some(49), d), ThresholdState::Active);
    }

    #[test]
    fn test_state_since_height() {
        let arena = build_arena(60, |_| SIGNAL, time_at);
        let d = dep(0, Bip9Deployment::NO_TIMEOUT, 0);
        let checker = VersionBitsConditionChecker::new(d);
        let mut cache = ThresholdConditionCache::new();

        // DEFINED reports 0 per BIP9.
        assert_eq!(
            checker.get_state_since_height_for(&arena, Some(5), &mut cache),
            0
        );
        // STARTED began at height 10, LOCKED_IN at 20, ACTIVE at 30.
        assert_eq!(
            checker.get_state_since_height_for(&arena, Some(15), &mut cache),
            10
        );
        assert_eq!(
            checker.get_state_since_height_for(&arena, Some(25), &mut cache),
            20
        );
        assert_eq!(
            checker.get_state_since_height_for(&arena, Some(35), &mut cache),
            30
        );
        assert_eq!(
            checker.get_state_since_height_for(&arena, Some(55), &mut cache),
            30
        );
    }

    #[test]
    fn test_state_since_height_is_zero_for_special_start_times() {
        let arena = build_arena(30, |_| SIGNAL, time_at);
        let checker = VersionBitsConditionChecker::new(dep(
            Bip9Deployment::ALWAYS_ACTIVE,
            Bip9Deployment::NO_TIMEOUT,
            0,
        ));
        let mut cache = ThresholdConditionCache::new();
        assert_eq!(
            checker.get_state_since_height_for(&arena, Some(25), &mut cache),
            0
        );

        let checker = VersionBitsConditionChecker::new(dep(
            Bip9Deployment::NEVER_ACTIVE,
            Bip9Deployment::NO_TIMEOUT,
            0,
        ));
        let mut cache = ThresholdConditionCache::new();
        assert_eq!(
            checker.get_state_since_height_for(&arena, Some(25), &mut cache),
            0
        );
    }

    #[test]
    fn test_statistics() {
        // Period 10, threshold 8, alternating signalling.
        let arena = build_arena(30, |h| if h % 2 == 0 { SIGNAL } else { NO_SIGNAL }, time_at);
        let checker = VersionBitsConditionChecker::new(dep(0, Bip9Deployment::NO_TIMEOUT, 0));

        // Block 14 is the 5th block of period 1 (heights 10..19).
        let mut signalling = Vec::new();
        let stats = checker.get_state_statistics_for(&arena, Some(14), Some(&mut signalling));
        assert_eq!(stats.period, 10);
        assert_eq!(stats.threshold, 8);
        assert_eq!(stats.elapsed, 5);
        assert_eq!(stats.count, 3); // heights 10, 12, 14
        assert_eq!(signalling, vec![true, false, true, false, true]);
        // 10 - 8 = 2 non-signalling blocks allowed; 5 - 3 = 2 seen. Still possible.
        assert!(stats.possible);

        // One block later there are 3 misses, which is one too many.
        let stats = checker.get_state_statistics_for(&arena, Some(15), None);
        assert_eq!(stats.elapsed, 6);
        assert_eq!(stats.count, 3);
        assert!(!stats.possible);
    }

    #[test]
    fn test_statistics_on_none_returns_period_and_threshold_only() {
        let arena = build_arena(5, |_| SIGNAL, time_at);
        let checker = VersionBitsConditionChecker::new(dep(0, Bip9Deployment::NO_TIMEOUT, 0));
        let stats = checker.get_state_statistics_for(&arena, None, None);
        assert_eq!(stats.period, 10);
        assert_eq!(stats.threshold, 8);
        assert_eq!(stats.elapsed, 0);
        assert_eq!(stats.count, 0);
    }

    #[test]
    fn test_mask_and_condition_version() {
        let checker = VersionBitsConditionChecker::new(dep(0, Bip9Deployment::NO_TIMEOUT, 0));
        assert_eq!(checker.mask(), 1 << 28);
        assert!(checker.condition_version(SIGNAL));
        assert!(!checker.condition_version(NO_SIGNAL));
        // Top bits must be exactly 001.
        assert!(!checker.condition_version(0x4000_0000 | (1 << 28)));
        // Old-style version numbers never signal.
        assert!(!checker.condition_version(VERSIONBITS_LAST_OLD_BLOCK_VERSION));
    }

    #[test]
    fn test_compute_block_version_testdummy_is_never_active_on_mainnet() {
        // Mainnet's testdummy is NEVER_ACTIVE, so no bits are ever set.
        let params = ConsensusParams::mainnet();
        let arena = build_arena(30, |_| SIGNAL, time_at);
        let mut cache = VersionBitsCache::new();
        assert_eq!(
            cache.compute_block_version(&arena, Some(29), &params),
            VERSIONBITS_TOP_BITS
        );
        assert!(!cache.is_active_after(&arena, Some(29), &params, DeploymentPos::TestDummy));
    }

    #[test]
    fn test_compute_block_version_signals_while_started() {
        // Regtest's testdummy starts at time 0, period 144, threshold 108.
        let params = ConsensusParams::regtest();
        let period = params.deployments[DeploymentPos::TestDummy.index()].period as i32;
        // Two full periods of non-signalling blocks: STARTED but not locked in.
        let arena = build_arena(period * 2 + 1, |_| NO_SIGNAL, time_at);
        let mut cache = VersionBitsCache::new();
        let version = cache.compute_block_version(&arena, Some((period * 2) as usize), &params);
        let bit = params.deployments[DeploymentPos::TestDummy.index()].bit;
        assert_eq!(version & VERSIONBITS_TOP_MASK, VERSIONBITS_TOP_BITS);
        assert_ne!(version & (1 << bit), 0, "STARTED deployments must signal");

        let status = cache.gbt_status(&arena, (period * 2) as usize, &params);
        assert_eq!(status.signalling.len(), 1);
        assert_eq!(status.signalling[0].name, "testdummy");
        assert_eq!(status.signalling[0].bit, bit);
        assert!(status.locked_in.is_empty());
        assert!(status.active.is_empty());
    }

    #[test]
    fn test_info_reports_states_and_since() {
        let arena = build_arena(60, |_| SIGNAL, time_at);
        let mut params = ConsensusParams::regtest();
        params.deployments[DeploymentPos::TestDummy.index()] =
            dep(0, Bip9Deployment::NO_TIMEOUT, 0);
        let mut cache = VersionBitsCache::new();

        // At height 19 the current period (10..19) is STARTED and the next
        // block, 20, starts a LOCKED_IN period.
        let info = cache.info(&arena, 19, &params, DeploymentPos::TestDummy);
        assert_eq!(info.current_state, "started");
        assert_eq!(info.next_state, "locked_in");
        assert_eq!(info.since, 10);
        let stats = info.stats.expect("signalling stats while STARTED");
        assert_eq!(stats.elapsed, 10);
        assert_eq!(stats.count, 10);
        assert_eq!(info.signalling_blocks.len(), 10);
        assert!(info.active_since.is_none());

        // At height 29 the period is LOCKED_IN and block 30 is ACTIVE.
        let info = cache.info(&arena, 29, &params, DeploymentPos::TestDummy);
        assert_eq!(info.current_state, "locked_in");
        assert_eq!(info.next_state, "active");
        assert_eq!(info.active_since, Some(30));
        // LOCKED_IN zeroes the threshold and clears `possible`, per Core.
        let stats = info.stats.expect("stats while LOCKED_IN");
        assert_eq!(stats.threshold, 0);
        assert!(!stats.possible);

        // At height 39 it is ACTIVE, since height 30.
        let info = cache.info(&arena, 39, &params, DeploymentPos::TestDummy);
        assert_eq!(info.current_state, "active");
        assert_eq!(info.since, 30);
        assert_eq!(info.active_since, Some(30));
        assert!(info.stats.is_none());
    }

    #[test]
    fn test_cache_clear() {
        let arena = build_arena(30, |_| SIGNAL, time_at);
        let params = ConsensusParams::regtest();
        let mut cache = VersionBitsCache::new();
        let v1 = cache.compute_block_version(&arena, Some(29), &params);
        cache.clear();
        let v2 = cache.compute_block_version(&arena, Some(29), &params);
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_unknown_activation_warning() {
        // Regtest warning checker: period = 144, threshold = 108 (75%).
        let chainparams = ChainParams::regtest();
        let period = chainparams.consensus.difficulty_adjustment_interval() as i32;
        // Signal an unused bit (bit 1) on every block.
        let unknown_bit = 1;
        let arena = build_arena(
            period * 3 + 1,
            |_| VERSIONBITS_TOP_BITS | (1 << unknown_bit),
            time_at,
        );
        let mut cache = VersionBitsCache::new();
        let warnings =
            cache.check_unknown_activations(&arena, Some((period * 3) as usize), &chainparams);
        assert!(
            warnings.iter().any(|(bit, _)| *bit == unknown_bit as usize),
            "expected a warning for bit {unknown_bit}, got {warnings:?}"
        );
    }

    #[test]
    fn test_no_warning_without_unknown_bits() {
        let chainparams = ChainParams::regtest();
        let period = chainparams.consensus.difficulty_adjustment_interval() as i32;
        let arena = build_arena(period * 3 + 1, |_| VERSIONBITS_TOP_BITS, time_at);
        let mut cache = VersionBitsCache::new();
        let warnings =
            cache.check_unknown_activations(&arena, Some((period * 3) as usize), &chainparams);
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
    }
}
