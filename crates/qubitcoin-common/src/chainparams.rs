//! Full chain parameters including consensus params and network specifics.
//!
//! Maps to: `src/kernel/chainparams.h` and `src/kernel/chainparams.cpp` in Bitcoin Core.
//!
//! Provides:
//! - [`Network`]: Enum identifying mainnet, testnet, regtest, or signet.
//! - [`ChainParams`]: Full chain parameters for a given network, including
//!   consensus params, default port, address prefixes, and genesis block hash.

use qubitcoin_consensus::ConsensusParams;
use qubitcoin_primitives::{BlockHash, Uint256};

/// Network type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
    Testnet4,
    Regtest,
    Signet,
}

/// Full chain parameters including consensus params and network specifics.
///
/// Port of Bitcoin Core's `CChainParams`.
pub struct ChainParams {
    /// Which network these parameters are for.
    pub network: Network,

    /// Consensus parameters (PoW limits, activation heights, etc.).
    pub consensus: ConsensusParams,

    /// Default p2p port.
    pub default_port: u16,

    /// Hash of the genesis block.
    pub genesis_block_hash: BlockHash,

    /// DNS seed hostnames for initial peer discovery.
    pub dns_seeds: Vec<String>,

    /// Base58 version byte for pay-to-pubkey-hash addresses.
    pub base58_prefix_pubkey_hash: [u8; 1],

    /// Base58 version byte for pay-to-script-hash addresses.
    pub base58_prefix_script_hash: [u8; 1],

    /// Base58 version byte for WIF-encoded private keys.
    pub base58_prefix_secret_key: [u8; 1],

    /// Bech32 human-readable part (e.g. "bc" for mainnet).
    pub bech32_hrp: String,

    /// BIP44 coin type (0 for mainnet, 1 for all test networks).
    pub bip44_coin_type: u32,

    /// Whether this is a test network.
    pub is_test_chain: bool,

    /// Minimum chain work for the chain to be considered valid.
    pub minimum_chain_work: Uint256,

    /// Assumed-valid block hash (skip full script verification before this).
    pub assumed_valid_block: BlockHash,
}

impl ChainParams {
    /// Parameters for the Bitcoin mainnet.
    pub fn mainnet() -> Self {
        ChainParams {
            network: Network::Mainnet,
            consensus: ConsensusParams::mainnet(),
            default_port: 8333,
            genesis_block_hash: BlockHash::from_hex(
                "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
            )
            .expect("valid mainnet genesis hash"),
            dns_seeds: vec![
                "seed.bitcoin.sipa.be".into(),
                "dnsseed.bluematt.me".into(),
                "seed.bitcoin.jonasschnelli.ch".into(),
                "seed.btc.petertodd.net".into(),
                "seed.bitcoin.sprovoost.nl".into(),
                "dnsseed.emzy.de".into(),
                "seed.bitcoin.wiz.biz".into(),
                "seed.mainnet.achownodes.xyz".into(),
            ],
            base58_prefix_pubkey_hash: [0x00],
            base58_prefix_script_hash: [0x05],
            base58_prefix_secret_key: [0x80],
            bech32_hrp: "bc".into(),
            bip44_coin_type: 0,
            is_test_chain: false,
            minimum_chain_work: ConsensusParams::mainnet().minimum_chain_work,
            assumed_valid_block: BlockHash::ZERO,
        }
    }

    /// Parameters for Bitcoin testnet3.
    pub fn testnet() -> Self {
        ChainParams {
            network: Network::Testnet,
            consensus: ConsensusParams::testnet(),
            default_port: 18333,
            genesis_block_hash: BlockHash::from_hex(
                "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
            )
            .expect("valid testnet genesis hash"),
            dns_seeds: vec![
                "testnet-seed.bitcoin.jonasschnelli.ch".into(),
                "seed.tbtc.petertodd.net".into(),
                "seed.testnet.bitcoin.sprovoost.nl".into(),
                "testnet-seed.bluematt.me".into(),
                "seed.testnet.achownodes.xyz".into(),
            ],
            base58_prefix_pubkey_hash: [0x6f],
            base58_prefix_script_hash: [0xc4],
            base58_prefix_secret_key: [0xef],
            bech32_hrp: "tb".into(),
            bip44_coin_type: 1,
            is_test_chain: true,
            minimum_chain_work: Uint256::ZERO,
            assumed_valid_block: BlockHash::ZERO,
        }
    }

    /// Parameters for the regtest (regression test) network.
    pub fn regtest() -> Self {
        ChainParams {
            network: Network::Regtest,
            consensus: ConsensusParams::regtest(),
            default_port: 18444,
            genesis_block_hash: BlockHash::from_hex(
                "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
            )
            .expect("valid regtest genesis hash"),
            dns_seeds: vec![],
            base58_prefix_pubkey_hash: [0x6f],
            base58_prefix_script_hash: [0xc4],
            base58_prefix_secret_key: [0xef],
            bech32_hrp: "bcrt".into(),
            bip44_coin_type: 1,
            is_test_chain: true,
            minimum_chain_work: Uint256::ZERO,
            assumed_valid_block: BlockHash::ZERO,
        }
    }

    /// Parameters for the signet network.
    pub fn signet() -> Self {
        ChainParams {
            network: Network::Signet,
            consensus: ConsensusParams::signet(),
            default_port: 38333,
            genesis_block_hash: BlockHash::from_hex(
                "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
            )
            .expect("valid signet genesis hash"),
            dns_seeds: vec![
                "seed.signet.bitcoin.sprovoost.nl".into(),
                "seed.signet.achownodes.xyz".into(),
            ],
            base58_prefix_pubkey_hash: [0x6f],
            base58_prefix_script_hash: [0xc4],
            base58_prefix_secret_key: [0xef],
            bech32_hrp: "tb".into(),
            bip44_coin_type: 1,
            is_test_chain: true,
            minimum_chain_work: Uint256::ZERO,
            assumed_valid_block: BlockHash::ZERO,
        }
    }

    /// Parameters for Bitcoin testnet4.
    pub fn testnet4() -> Self {
        ChainParams {
            network: Network::Testnet4,
            consensus: ConsensusParams::testnet4(),
            default_port: 48333,
            genesis_block_hash: BlockHash::from_hex(
                "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043",
            )
            .expect("valid testnet4 genesis hash"),
            dns_seeds: vec![
                "seed.testnet4.bitcoin.sprovoost.nl.".into(),
                "seed.testnet4.wiz.biz.".into(),
            ],
            base58_prefix_pubkey_hash: [0x6f],
            base58_prefix_script_hash: [0xc4],
            base58_prefix_secret_key: [0xef],
            bech32_hrp: "tb".into(),
            bip44_coin_type: 1,
            is_test_chain: true,
            minimum_chain_work: Uint256::ZERO,
            assumed_valid_block: BlockHash::ZERO,
        }
    }

    /// Get chain parameters for a given network.
    pub fn for_network(network: Network) -> Self {
        match network {
            Network::Mainnet => Self::mainnet(),
            Network::Testnet => Self::testnet(),
            Network::Testnet4 => Self::testnet4(),
            Network::Regtest => Self::regtest(),
            Network::Signet => Self::signet(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Genesis hash tests --

    #[test]
    fn test_mainnet_genesis_hash() {
        let params = ChainParams::mainnet();
        assert_eq!(
            params.genesis_block_hash.to_hex(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
    }

    #[test]
    fn test_testnet_genesis_hash() {
        let params = ChainParams::testnet();
        assert_eq!(
            params.genesis_block_hash.to_hex(),
            "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
        );
    }

    #[test]
    fn test_regtest_genesis_hash() {
        let params = ChainParams::regtest();
        assert_eq!(
            params.genesis_block_hash.to_hex(),
            "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
        );
    }

    #[test]
    fn test_signet_genesis_hash() {
        let params = ChainParams::signet();
        assert_eq!(
            params.genesis_block_hash.to_hex(),
            "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"
        );
    }

    // -- Default port tests --

    #[test]
    fn test_mainnet_default_port() {
        let params = ChainParams::mainnet();
        assert_eq!(params.default_port, 8333);
    }

    #[test]
    fn test_testnet_default_port() {
        let params = ChainParams::testnet();
        assert_eq!(params.default_port, 18333);
    }

    #[test]
    fn test_regtest_default_port() {
        let params = ChainParams::regtest();
        assert_eq!(params.default_port, 18444);
    }

    #[test]
    fn test_signet_default_port() {
        let params = ChainParams::signet();
        assert_eq!(params.default_port, 38333);
    }

    // -- Address prefix tests --

    #[test]
    fn test_mainnet_address_prefixes() {
        let params = ChainParams::mainnet();
        assert_eq!(params.base58_prefix_pubkey_hash, [0x00]);
        assert_eq!(params.base58_prefix_script_hash, [0x05]);
        assert_eq!(params.base58_prefix_secret_key, [0x80]);
        assert_eq!(params.bech32_hrp, "bc");
        assert_eq!(params.bip44_coin_type, 0);
        assert!(!params.is_test_chain);
    }

    #[test]
    fn test_testnet_address_prefixes() {
        let params = ChainParams::testnet();
        assert_eq!(params.base58_prefix_pubkey_hash, [0x6f]);
        assert_eq!(params.base58_prefix_script_hash, [0xc4]);
        assert_eq!(params.base58_prefix_secret_key, [0xef]);
        assert_eq!(params.bech32_hrp, "tb");
        assert_eq!(params.bip44_coin_type, 1);
        assert!(params.is_test_chain);
    }

    #[test]
    fn test_regtest_address_prefixes() {
        let params = ChainParams::regtest();
        assert_eq!(params.base58_prefix_pubkey_hash, [0x6f]);
        assert_eq!(params.base58_prefix_script_hash, [0xc4]);
        assert_eq!(params.base58_prefix_secret_key, [0xef]);
        assert_eq!(params.bech32_hrp, "bcrt");
        assert_eq!(params.bip44_coin_type, 1);
        assert!(params.is_test_chain);
    }

    #[test]
    fn test_signet_address_prefixes() {
        let params = ChainParams::signet();
        assert_eq!(params.base58_prefix_pubkey_hash, [0x6f]);
        assert_eq!(params.base58_prefix_script_hash, [0xc4]);
        assert_eq!(params.base58_prefix_secret_key, [0xef]);
        assert_eq!(params.bech32_hrp, "tb");
        assert_eq!(params.bip44_coin_type, 1);
        assert!(params.is_test_chain);
    }

    // -- for_network dispatch test --

    #[test]
    fn test_for_network_dispatch() {
        let networks = [
            Network::Mainnet,
            Network::Testnet,
            Network::Testnet4,
            Network::Regtest,
            Network::Signet,
        ];
        let expected_ports = [8333u16, 18333, 48333, 18444, 38333];

        for (network, expected_port) in networks.iter().zip(expected_ports.iter()) {
            let params = ChainParams::for_network(*network);
            assert_eq!(params.network, *network);
            assert_eq!(params.default_port, *expected_port);
        }
    }

    #[test]
    fn test_mainnet_consensus_params() {
        let params = ChainParams::mainnet();
        assert_eq!(params.consensus.subsidy_halving_interval, 210_000);
        assert_eq!(params.consensus.pow_target_spacing, 600);
        assert!(!params.consensus.pow_allow_min_difficulty_blocks);
        assert!(!params.consensus.pow_no_retargeting);
    }

    #[test]
    fn test_regtest_consensus_params() {
        let params = ChainParams::regtest();
        assert_eq!(params.consensus.subsidy_halving_interval, 150);
        assert!(params.consensus.pow_allow_min_difficulty_blocks);
        assert!(params.consensus.pow_no_retargeting);
    }

    #[test]
    fn test_mainnet_has_dns_seeds() {
        let params = ChainParams::mainnet();
        assert!(!params.dns_seeds.is_empty());
    }

    #[test]
    fn test_regtest_has_no_dns_seeds() {
        let params = ChainParams::regtest();
        assert!(params.dns_seeds.is_empty());
    }
}
