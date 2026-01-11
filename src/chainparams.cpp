// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Copyright (c) 2014-2025 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <chainparamsbase.h>
#include <common/args.h>
#include <consensus/params.h>
#include <deploymentinfo.h>
#include <logging.h>
#include <tinyformat.h>
#include <util/chaintype.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <assert.h>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>

#include <chainparamsseeds.h>

// Wentuno modifications
static CBlock CreateGenesisBlock(const std::string& pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>(pszTimestamp.begin(), pszTimestamp.end());
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "20/Jan/2026 Seventeen years and seventeen days late to the beginning. Nine years until the absolute end. Then nothing. Ever.";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = CBaseChainParams::MAIN;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 210000; // placeholder - we will override with linear
        consensus.BIP16Exception = uint256S("0x00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b6d5b2d9b2c2e9"); // example
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.CSVHeight = 0;
        consensus.SegwitHeight = 0;
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // low difficulty for genesis
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // 2 weeks
        consensus.nPowTargetSpacing = 10 * 60;  // 10 MINUTES - WENTUNO CHANGE
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% for mainnet
        consensus.nMinerConfirmationWindow = 2016;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        /**
         * The message bytes to be included in the alert messages.
         */
        pchMessageStart[0] = 0xf1;   // Unique for Wentuno - random bytes
        pchMessageStart[1] = 0xc2;
        pchMessageStart[2] = 0xb3;
        pchMessageStart[3] = 0xa4;

        nDefaultPort = 22556;  // Change from Syscoin's port to avoid conflict

        genesis = CreateGenesisBlock(1768867200, 2083236893, 0x1e0ffff0, 1, 50 * COIN);  // Jan 20 2026 00:00 UTC, low nonce/bits for easy mining

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x0000000000000000000000000000000000000000000000000000000000000000")); // placeholder - will update after first run

        // TODO: Add DNS seeds, checkpoints, etc. later

        // AuxPoW / merge-mining params (Syscoin compatible)
        consensus.nAuxpowChainId = 0x0001; // adjust if needed
        consensus.nAuxpowStartHeight = 0;  // from genesis
        consensus.fStrictChainId = true;
        consensus.nLegacyBlocksBefore = -1; // always allow AuxPoW

        // Wentuno specific - will expand later for linear emission, quantum etc.
    }
};

const CChainParams &Params() {
    static std::unique_ptr<CChainParams> globalParams = std::make_unique<CMainParams>();
    return *globalParams;
}

// Add TestNet/RegTest stubs if needed later
std::unique_ptr<const CChainParams> CreateChainParams(const ArgsManager& args, const ChainType chainType) {
    switch (chainType) {
    case ChainType::MAIN:
        return std::make_unique<CMainParams>();
    default:
        throw std::runtime_error(strprintf("%s: Unknown chain type %d", __func__, int(chainType)));
    }
}