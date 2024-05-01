#include <iostream>
#include <cstdint>
#include <string>
#include <vector>
#include <script/script.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <consensus/merkle.h>
#include <uint256.h>
#include <arith_uint256.h>
#include <util/strencodings.h>

static std::pair<CBlock, uint32_t> MineGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward) {
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime = nTime;
    genesis.nBits = nBits;
    genesis.nNonce = 0; // Initialize nonce at zero
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);

    uint256 hashTarget = uint256().SetCompact(nBits);
    uint256 hash;
    while (true) {
        hash = genesis.GetHash();
        if (hash <= hashTarget) {
            break; // Suitable nonce found
        }
        genesis.nNonce++;
        if (genesis.nNonce == 0) {
            std::cerr << "Nonce overflow" << std::endl;
            throw std::runtime_error("Nonce overflowed, mining failed");
        }
    }
    return {genesis, genesis.nNonce}; // Return both the block and the nonce
}

int main() {
    const char* pszTimestamp = "On 04/20/2024 Sean and Danny created a new genesis";
    CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;

    try {
        auto [genesisBlock, nonce] = MineGenesisBlock(pszTimestamp, genesisOutputScript, 1231006505, 0x1d00ffff, 1, 50 * COIN);
        std::cout << "Mined genesis block with nonce: " << nonce << std::endl;
        std::cout << "Genesis block hash: " << genesisBlock.GetHash().ToString() << std::endl;

        // Output the nonce and hash so it can be hardcoded later
        std::cout << "Hardcode this nonce: " << nonce << std::endl;
        std::cout << "Hardcode this hash: " << genesisBlock.GetHash().ToString() << std::endl;
    } catch (const std::runtime_error& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
