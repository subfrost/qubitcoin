//! Consensus parameters for different networks.
//! Maps to: src/consensus/params.h, src/kernel/chainparams.cpp

use qubitcoin_primitives::{BlockHash, Uint256};
use std::collections::HashMap;

/// The default signet challenge script (BIP325), as raw serialized script bytes.
///
/// This is a 1-of-2 multisig over the two public keys controlled by the signet
/// maintainers:
///
/// ```text
/// OP_1 <03ad5e0e..be43> <0359ef50..e6c4> OP_2 OP_CHECKMULTISIG
/// ```
///
/// Maps to: `kernel::SIGNET_DEFAULT_CHALLENGE` in `src/kernel/signet.h`.
pub const SIGNET_DEFAULT_CHALLENGE: [u8; 71] = [
    0x51, 0x21, 0x03, 0xad, 0x5e, 0x0e, 0xda, 0xd1, 0x8c, 0xb1, 0xf0, 0xfc, 0x0d, 0x28, 0xa3, 0xd4,
    0xf1, 0xf3, 0xe4, 0x45, 0x64, 0x03, 0x37, 0x48, 0x9a, 0xbb, 0x10, 0x40, 0x4f, 0x2d, 0x1e, 0x08,
    0x6b, 0xe4, 0x30, 0x21, 0x03, 0x59, 0xef, 0x50, 0x21, 0x96, 0x4f, 0xe2, 0x2d, 0x6f, 0x8e, 0x05,
    0xb2, 0x46, 0x3c, 0x95, 0x40, 0xce, 0x96, 0x88, 0x3f, 0xe3, 0xb2, 0x78, 0x76, 0x0f, 0x04, 0x8f,
    0x51, 0x89, 0xf2, 0xe6, 0xc4, 0x52, 0xae,
];

/// Maximum amount a block's timestamp may go backwards relative to its parent
/// at a difficulty adjustment boundary, when BIP94 is enforced (seconds).
///
/// Maps to: `MAX_TIMEWARP` in `src/consensus/consensus.h`.
pub const MAX_TIMEWARP: i64 = 600;

/// Identifies a BIP9 (versionbits) deployment.
///
/// Every historical soft fork Bitcoin Core once deployed this way (CSV, segwit,
/// taproot) is now *buried* — enforced from a hardcoded height — so upstream is
/// left with only the test dummy. New deployments are added here.
///
/// Maps to: `Consensus::DeploymentPos` in `src/consensus/params.h`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(usize)]
pub enum DeploymentPos {
    /// Deployment used only by tests; never active on a real network.
    TestDummy = 0,
}

/// Number of versionbits deployments defined.
///
/// Maps to: `Consensus::MAX_VERSION_BITS_DEPLOYMENTS`.
pub const MAX_VERSION_BITS_DEPLOYMENTS: usize = 1;

impl DeploymentPos {
    /// All deployments, in index order.
    pub const ALL: [DeploymentPos; MAX_VERSION_BITS_DEPLOYMENTS] = [DeploymentPos::TestDummy];

    /// Index into [`ConsensusParams::deployments`].
    pub fn index(self) -> usize {
        self as usize
    }

    /// Short name, as used by the `getblockchaininfo` / `getdeploymentinfo` RPCs.
    pub fn name(self) -> &'static str {
        match self {
            DeploymentPos::TestDummy => "testdummy",
        }
    }
}

/// Parameters of one individual consensus rule change deployed using BIP9.
///
/// Maps to: `Consensus::BIP9Deployment` in `src/consensus/params.h`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bip9Deployment {
    /// Bit position selected in the block's `nVersion`.
    pub bit: i32,
    /// Median-time-past at which miner signalling may begin. May be in the past.
    pub start_time: i64,
    /// Median-time-past at which the deployment attempt expires.
    pub timeout: i64,
    /// If lock-in occurs, delay activation until at least this height. Note
    /// that activation still only happens on a period boundary.
    pub min_activation_height: i32,
    /// Number of blocks in a signalling period (normally the retarget interval).
    pub period: u32,
    /// Blocks within a period that must signal for the deployment to lock in.
    pub threshold: u32,
}

impl Bip9Deployment {
    /// Timeout value far enough in the future to never be reached.
    pub const NO_TIMEOUT: i64 = i64::MAX;
    /// `start_time` marking a deployment that is active from genesis. Test-only:
    /// it skips the three-period activation dance.
    pub const ALWAYS_ACTIVE: i64 = -1;
    /// `start_time` marking a deployment that can never activate. Used to land
    /// the code for a fork before choosing its schedule.
    pub const NEVER_ACTIVE: i64 = -2;

    /// The `testdummy` deployment as configured for a given network.
    const fn testdummy(start_time: i64, threshold: u32, period: u32) -> Self {
        Bip9Deployment {
            bit: 28,
            start_time,
            timeout: Self::NO_TIMEOUT,
            min_activation_height: 0, // No activation delay.
            period,
            threshold,
        }
    }
}

/// Consensus parameters for a network.
///
/// Port of Bitcoin Core's Consensus::Params.
#[derive(Clone, Debug)]
pub struct ConsensusParams {
    /// Hash of the genesis block for this network.
    ///
    /// Maps to: `Consensus::Params::hashGenesisBlock`.
    pub genesis_hash: BlockHash,
    /// Block height at which BIP34 becomes active (block height in coinbase).
    pub bip34_height: i32,
    /// Block height at which BIP65 becomes active (CHECKLOCKTIMEVERIFY).
    pub bip65_height: i32,
    /// Block height at which BIP66 becomes active (strict DER signatures).
    pub bip66_height: i32,
    /// Block height at which CSV (BIP68, BIP112, BIP113) becomes active.
    pub csv_height: i32,
    /// Block height at which segwit (BIP141, BIP143, BIP147) becomes active.
    pub segwit_height: i32,
    /// Block height at which Taproot (BIP341, BIP342) becomes active.
    /// -1 means never active. Bitcoin Core uses version bits for this on
    /// mainnet, but we simplify to a height for the same effect.
    pub taproot_height: i32,

    /// Map of block hashes to script verification flag overrides.
    /// Used for the two historical blocks that violated P2SH/Taproot rules.
    /// Maps to: `Consensus::Params::script_flag_exceptions` in Bitcoin Core.
    pub script_flag_exceptions: HashMap<BlockHash, u32>,

    /// Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period.
    pub rule_change_activation_threshold: u32,
    /// Number of blocks in a retargeting period.
    pub miner_confirmation_window: u32,

    /// Per-deployment BIP9 parameters, indexed by [`DeploymentPos::index`].
    ///
    /// Maps to: `Consensus::Params::vDeployments`.
    pub deployments: [Bip9Deployment; MAX_VERSION_BITS_DEPLOYMENTS],

    /// Don't warn about unknown BIP9 activations below this height.
    ///
    /// This prevents warning about the historical CSV, segwit and taproot
    /// activations, whose version bits are still set in old blocks.
    ///
    /// Maps to: `Consensus::Params::MinBIP9WarningHeight`.
    pub min_bip9_warning_height: i32,

    /// Proof-of-work upper bound. No target may exceed this value.
    pub pow_limit: Uint256,
    /// Target timespan for difficulty adjustment, in seconds (e.g., 2 weeks for mainnet).
    pub pow_target_timespan: i64,
    /// Target time between blocks, in seconds (e.g., 600 for mainnet = 10 minutes).
    pub pow_target_spacing: i64,
    /// Whether to allow minimum-difficulty blocks (testnet rule).
    pub pow_allow_min_difficulty_blocks: bool,
    /// Whether to disable difficulty retargeting entirely (regtest rule).
    pub pow_no_retargeting: bool,

    /// Enforce the BIP94 timewarp attack mitigation.
    ///
    /// When set, two extra rules apply:
    ///
    /// 1. The first block of every difficulty adjustment interval must have a
    ///    timestamp no earlier than `prev_block_time - MAX_TIMEWARP` (600s).
    ///    See [`crate::MAX_TIMEWARP`] and `contextual_check_block_header`.
    /// 2. The retarget calculation bases the new target on the `nBits` of the
    ///    *first* block of the previous period rather than the last, so the
    ///    min-difficulty exception cannot leak into the real difficulty. On
    ///    testnet4 this is the "block storm" mitigation.
    ///
    /// Active on testnet4; configurable on regtest. Never on mainnet,
    /// testnet3 or signet.
    ///
    /// Maps to: `Consensus::Params::enforce_BIP94`.
    pub enforce_bip94: bool,

    /// If true, witness commitments contain a payload equal to a Bitcoin
    /// Script solution to the signet challenge (BIP325).
    ///
    /// Maps to: `Consensus::Params::signet_blocks`.
    pub signet_blocks: bool,
    /// The signet challenge script, as raw serialized script bytes (BIP325).
    ///
    /// Maps to: `Consensus::Params::signet_challenge`.
    pub signet_challenge: Vec<u8>,

    /// The best chain should have at least this much work.
    pub minimum_chain_work: Uint256,

    /// Block hash that must be in the chain.
    pub default_assume_valid: BlockHash,

    /// Subsidy halving interval (blocks).
    pub subsidy_halving_interval: i32,
}

impl ConsensusParams {
    /// Mainnet consensus parameters.
    pub fn mainnet() -> Self {
        // Historical blocks that violated script rules.
        // BIP16 exception + Taproot exception (P2SH+WITNESS only, no TAPROOT).
        let mut exceptions = HashMap::new();
        // Block that violated BIP16 P2SH rules:
        if let Some(h) =
            BlockHash::from_hex("00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22")
        {
            exceptions.insert(h, 0u32); // SCRIPT_VERIFY_NONE
        }
        // Block that violated Taproot rules (only P2SH+WITNESS):
        if let Some(h) =
            BlockHash::from_hex("0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad")
        {
            exceptions.insert(h, 0x801u32); // SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS
        }

        ConsensusParams {
            genesis_hash: BlockHash::from_hex(
                "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
            )
            .unwrap_or(BlockHash::ZERO),
            bip34_height: 227931,
            bip65_height: 388381,
            bip66_height: 363725,
            csv_height: 419328,
            segwit_height: 481824,
            taproot_height: 709632,
            script_flag_exceptions: exceptions,
            rule_change_activation_threshold: 1916,
            miner_confirmation_window: 2016,
            // taproot activation height + miner confirmation window
            min_bip9_warning_height: 711648,
            pow_limit: Uint256::from_hex(
                "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            )
            .unwrap(),
            pow_target_timespan: 14 * 24 * 60 * 60, // 2 weeks
            pow_target_spacing: 10 * 60,            // 10 minutes
            pow_allow_min_difficulty_blocks: false,
            pow_no_retargeting: false,
            enforce_bip94: false,
            signet_blocks: false,
            signet_challenge: Vec::new(),
            minimum_chain_work: Uint256::from_hex(
                "000000000000000000000000000000000000000145ec036acc5ba740052af1a0",
            )
            .unwrap(),
            default_assume_valid: BlockHash::from_hex(
                // height 966143
                "00000000000000000000748969ec33043c0e52a763c6dd5193861f559f2c72e3",
            )
            .unwrap_or(BlockHash::ZERO),
            subsidy_halving_interval: 210_000,
            deployments: [Bip9Deployment::testdummy(Bip9Deployment::NEVER_ACTIVE, 1815, 2016)],
        }
    }

    /// Testnet3 consensus parameters.
    pub fn testnet() -> Self {
        // BIP16 exception block on testnet3.
        let mut exceptions = HashMap::new();
        if let Some(h) =
            BlockHash::from_hex("00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105")
        {
            exceptions.insert(h, 0u32); // SCRIPT_VERIFY_NONE
        }

        ConsensusParams {
            genesis_hash: BlockHash::from_hex(
                "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
            )
            .unwrap_or(BlockHash::ZERO),
            bip34_height: 21111,
            bip65_height: 581885,
            bip66_height: 330776,
            csv_height: 770112,
            segwit_height: 834624,
            taproot_height: 0, // always active on testnet3
            script_flag_exceptions: exceptions,
            rule_change_activation_threshold: 1512,
            miner_confirmation_window: 2016,
            // taproot activation height + miner confirmation window
            min_bip9_warning_height: 2013984,
            pow_limit: Uint256::from_hex(
                "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            )
            .unwrap(),
            pow_target_timespan: 14 * 24 * 60 * 60,
            pow_target_spacing: 10 * 60,
            pow_allow_min_difficulty_blocks: true,
            pow_no_retargeting: false,
            enforce_bip94: false,
            signet_blocks: false,
            signet_challenge: Vec::new(),
            minimum_chain_work: Uint256::from_hex(
                "0000000000000000000000000000000000000000000017f49f702147f10c0eb6",
            )
            .unwrap(),
            default_assume_valid: BlockHash::from_hex(
                // height 5128859
                "00000000b318a3703d14a844c55ef507f4c2fc8f8766e24271fd43c180c51637",
            )
            .unwrap_or(BlockHash::ZERO),
            subsidy_halving_interval: 210_000,
            deployments: [Bip9Deployment::testdummy(Bip9Deployment::NEVER_ACTIVE, 1512, 2016)],
        }
    }

    /// Regtest consensus parameters.
    ///
    /// Matches Bitcoin Core: all BIPs active from height 1 (or 0 for segwit/taproot).
    pub fn regtest() -> Self {
        ConsensusParams {
            genesis_hash: BlockHash::from_hex(
                "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
            )
            .unwrap_or(BlockHash::ZERO),
            bip34_height: 1,
            bip65_height: 1,
            bip66_height: 1,
            csv_height: 1,
            segwit_height: 0,  // always active
            taproot_height: 0, // always active
            script_flag_exceptions: HashMap::new(),
            rule_change_activation_threshold: 108,
            miner_confirmation_window: 144,
            min_bip9_warning_height: 0,
            pow_limit: Uint256::from_hex(
                "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            )
            .unwrap(),
            pow_target_timespan: 24 * 60 * 60, // 1 day (Bitcoin Core regtest)
            pow_target_spacing: 10 * 60,
            pow_allow_min_difficulty_blocks: true,
            pow_no_retargeting: true,
            // Core makes this configurable on regtest via -testactivationheight
            // style options; default off.
            enforce_bip94: false,
            signet_blocks: false,
            signet_challenge: Vec::new(),
            minimum_chain_work: Uint256::ZERO,
            default_assume_valid: BlockHash::ZERO,
            subsidy_halving_interval: 150,
            deployments: [Bip9Deployment::testdummy(0, 108, 144)],
        }
    }

    /// Signet consensus parameters.
    ///
    /// Matches Bitcoin Core: all BIPs active from height 1, custom powLimit.
    pub fn signet() -> Self {
        ConsensusParams {
            genesis_hash: BlockHash::from_hex(
                "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
            )
            .unwrap_or(BlockHash::ZERO),
            bip34_height: 1,
            bip65_height: 1,
            bip66_height: 1,
            csv_height: 1,
            segwit_height: 1,
            taproot_height: 0, // always active
            script_flag_exceptions: HashMap::new(),
            rule_change_activation_threshold: 1916,
            miner_confirmation_window: 2016,
            min_bip9_warning_height: 0,
            pow_limit: Uint256::from_hex(
                "00000377ae000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            pow_target_timespan: 14 * 24 * 60 * 60,
            pow_target_spacing: 10 * 60,
            pow_allow_min_difficulty_blocks: false,
            pow_no_retargeting: false,
            enforce_bip94: false,
            signet_blocks: true,
            signet_challenge: SIGNET_DEFAULT_CHALLENGE.to_vec(),
            minimum_chain_work: Uint256::from_hex(
                "00000000000000000000000000000000000000000000000000001090e9dc1520",
            )
            .unwrap(),
            default_assume_valid: BlockHash::from_hex(
                // height 321295
                "00000002a5e0ba0498f1e9f4591af0b66b63c654665efe65206fd0ae7bbaf923",
            )
            .unwrap_or(BlockHash::ZERO),
            subsidy_halving_interval: 210_000,
            deployments: [Bip9Deployment::testdummy(Bip9Deployment::NEVER_ACTIVE, 1815, 2016)],
        }
    }

    /// Testnet4 consensus parameters.
    ///
    /// Matches Bitcoin Core: all BIPs active from height 1, Taproot always active.
    pub fn testnet4() -> Self {
        ConsensusParams {
            genesis_hash: BlockHash::from_hex(
                "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043",
            )
            .unwrap_or(BlockHash::ZERO),
            bip34_height: 1,
            bip65_height: 1,
            bip66_height: 1,
            csv_height: 1,
            segwit_height: 1,
            taproot_height: 0, // always active
            script_flag_exceptions: HashMap::new(),
            rule_change_activation_threshold: 1512,
            miner_confirmation_window: 2016,
            min_bip9_warning_height: 0,
            pow_limit: Uint256::from_hex(
                "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            )
            .unwrap(),
            pow_target_timespan: 14 * 24 * 60 * 60,
            pow_target_spacing: 10 * 60,
            pow_allow_min_difficulty_blocks: true,
            pow_no_retargeting: false,
            // Testnet4 enforces BIP94: timewarp mitigation + block storm
            // mitigation. This is a consensus rule, not policy.
            enforce_bip94: true,
            signet_blocks: false,
            signet_challenge: Vec::new(),
            minimum_chain_work: Uint256::from_hex(
                "000000000000000000000000000000000000000000000e346a558455ade8eca9",
            )
            .unwrap(),
            default_assume_valid: BlockHash::from_hex(
                // height 151604
                "0000000021df65b91665a342e26ceb05e54826ad7d8fcd40316230058fa3b865",
            )
            .unwrap_or(BlockHash::ZERO),
            subsidy_halving_interval: 210_000,
            deployments: [Bip9Deployment::testdummy(Bip9Deployment::NEVER_ACTIVE, 1512, 2016)],
        }
    }

    /// Get the difficulty adjustment interval (how many blocks between retargets).
    pub fn difficulty_adjustment_interval(&self) -> i64 {
        self.pow_target_timespan / self.pow_target_spacing
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mainnet_params() {
        let params = ConsensusParams::mainnet();
        assert_eq!(params.subsidy_halving_interval, 210_000);
        assert_eq!(params.difficulty_adjustment_interval(), 2016);
        assert_eq!(params.pow_target_spacing, 600);
    }

    #[test]
    fn test_regtest_params() {
        let params = ConsensusParams::regtest();
        assert_eq!(params.subsidy_halving_interval, 150);
        assert!(params.pow_no_retargeting);
        assert!(params.pow_allow_min_difficulty_blocks);
        assert_eq!(params.segwit_height, 0);
    }
}
