// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Copyright (c) 2014-2018 The riecoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>
#include "util.h"

bool isAfterFork1(int nHeight, const Consensus::Params& params)
{
    if (params.fPowAllowMinDifficultyBlocks) // testnet
    {
        return nHeight > 3000;
    }

    return nHeight > 159000;
}

bool isInSuperblockInterval(int nHeight, const Consensus::Params& params)
{
    return ( (nHeight / params.DifficultyAdjustmentInterval()) % 14) == 12; // once per week
}

bool isSuperblock(int nHeight, const Consensus::Params& params)
{
    return ((nHeight % params.DifficultyAdjustmentInterval()) == 144) && isInSuperblockInterval(nHeight, params);
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        // SuperBlocks
        if (isAfterFork1(pindexLast->nHeight+1, params))
        {
            if (isSuperblock(pindexLast->nHeight+1, params))
            {
                arith_uint256 bnNewPow;
                bnNewPow.SetCompact(pindexLast->nBits);
                bnNewPow *= 95859; // superblock is 4168/136 times more difficult
                bnNewPow >>= 16; // 95859/65536 ~= (4168/136) ^ 1/9
                LogPrintf("GetNextWorkRequired superblock difficulty:  %d    %08x  %s\n", pindexLast->nHeight+1, bnNewPow.GetCompact(), bnNewPow.ToString());
                return bnNewPow.GetCompact();
            }
            else if (isSuperblock(pindexLast->nHeight+1-1, params)) // right after superblock, go back to previous diff
            {
                return pindexLast->pprev->nBits;
            }
        }

        // TestNet
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 2.5 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
//                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                // clo1 - this matches bug in 0.10.2, will always return previous block because it compares with non-compacted size
                // after first min-difficulty block, remaining blocks in interval will also be min-difficulty
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == RIECOIN_MIN_PRIME_SIZE)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be nTargetTimespan worth of blocks
    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
    assert(nHeightFirst >= 0);
    if (nHeightFirst == 0)
        nHeightFirst++;
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (pindexLast->nHeight+1 >= params.DifficultyAdjustmentInterval()*2) {
        if (nActualTimespan < params.nPowTargetTimespan/4)
            nActualTimespan = params.nPowTargetTimespan/4;
        if (nActualTimespan > params.nPowTargetTimespan*4)
            nActualTimespan = params.nPowTargetTimespan*4;
    }

    // Retarget
    const arith_uint256 arPowLimit = UintToArith256(params.powLimit);
    const uint64_t iPowLimit = arPowLimit.GetLow64();

    arith_uint256 arDiff;
    arDiff.SetCompact(pindexLast->nBits);
    const uint64_t iDiff = arDiff.GetLow64();
    
    // 9th power (3+RIECOIN_CONSTELLATION_SIZE)
    mpz_t gmpNewPow;
    mpz_init(gmpNewPow);
    mpz_ui_pow_ui(gmpNewPow, iDiff, 3 + RIECOIN_CONSTELLATION_SIZE);

    // gmpNewPow*params.nPowTargetTimespan/nActualTimespan
    mpz_mul_ui(gmpNewPow, gmpNewPow, (uint64_t)params.nPowTargetTimespan);
    mpz_fdiv_q_ui(gmpNewPow, gmpNewPow, (uint64_t)nActualTimespan);
    
    if (isAfterFork1(pindexLast->nHeight+1, params))
    {
        if (isInSuperblockInterval(pindexLast->nHeight+1, params)) // once per week, our interval contains a superblock
        {
            // * 136/150 to compensate for difficult superblock
            mpz_mul_ui(gmpNewPow, gmpNewPow, 68);
            mpz_fdiv_q_ui(gmpNewPow, gmpNewPow, 75);
            LogPrintf("Adjusted because has superblock\n");
        }
        else if (isInSuperblockInterval(pindexLast->nHeight, params))
        {
            // * 150/136 to compensate for previous adj
            mpz_mul_ui(gmpNewPow, gmpNewPow, 75);
            mpz_fdiv_q_ui(gmpNewPow, gmpNewPow, 68);
            LogPrintf("Adjusted because had superblock\n");
        }
    }

    uint64_t iNew;

    mpz_t gmpNew;
    mpz_init(gmpNew);
    mpz_root(gmpNew, gmpNewPow, 3+RIECOIN_CONSTELLATION_SIZE);
    
    if (mpz_cmp_ui(gmpNew, (uint64_t)-1) > 0)
		iNew = (uint64_t)-1;
	else
		iNew = mpz_get_ui(gmpNew);

    if (iNew < iPowLimit)
        iNew = iPowLimit;
 
    mpz_clear(gmpNewPow);
    mpz_clear(gmpNew);

    arith_uint256 arNew = iNew;

    return arNew.GetCompact();
}

unsigned int generatePrimeBase(mpz_t gmpTarget, uint256 hash, bitsType compactBits)
{
    mpz_init_set_ui(gmpTarget, 1);
    mpz_mul_2exp(gmpTarget, gmpTarget, ZEROS_BEFORE_HASH_IN_PRIME); // 1 << ZEROS_BEFORE_HASH_IN_PRIME
    
    arith_uint256 arHash = UintToArith256(hash);
    for ( int i = 0; i < 256; i++ )
    {
        mpz_mul_2exp(gmpTarget, gmpTarget, 1);
        mpz_add_ui(gmpTarget, gmpTarget, (arHash.GetLow32() & 1));
        arHash >>= 1;
    }

    arith_uint256 arBits;
    arBits.SetCompact(compactBits);
    if( arBits > arBits.GetLow32() ) // the protocol stores a compact big int so it supports larger values, but this version of the client does not
    {
        arBits = (uint32_t)-1; // saturate diff at (2**32) - 1, this should be enough for some years ;)
    }

    const unsigned int significativeDigits =  1 + ZEROS_BEFORE_HASH_IN_PRIME + 256;
    unsigned int trailingZeros = arBits.GetLow32();
    if( trailingZeros < significativeDigits )
        return 0;

    trailingZeros -= significativeDigits;
    mpz_mul_2exp(gmpTarget, gmpTarget, trailingZeros); // gmpTarget <<= trailingZeros

    return trailingZeros;
}

bool CheckProofOfWork(uint256 hash, bitsType compactBits, offsetType delta, const Consensus::Params& params)
{
    if (hash == params.hashGenesisBlockForPoW)
        return true;

    mpz_t gmpTarget; // init in generatePrimeBase
    unsigned int trailingZeros = generatePrimeBase(gmpTarget, hash, compactBits);

    if ((trailingZeros < 256) && !params.fPowAllowMinDifficultyBlocks)
    {
        arith_uint256 deltaLimit = 1;
        deltaLimit = deltaLimit<<trailingZeros;
        if( delta >= deltaLimit )
            return error("CheckProofOfWork() : candidate larger than allowed %s of %s", delta.ToString().c_str(), deltaLimit.ToString().c_str() );
    }

    mpz_t gmpDelta;
    mpz_init(gmpDelta);

    uint256 u256Delta = ArithToUint256(delta);
    mpz_import(gmpDelta, 8, -1, sizeof(uint32_t), 0, 0, u256Delta.begin());

    mpz_add(gmpTarget, gmpTarget, gmpDelta);
    mpz_clear(gmpDelta);

    if (mpz_fdiv_ui(gmpTarget, 210) != 97) // target % 210 = 97
        return error("CheckProofOfWork() : not valid pow");

    // first we do a single test to quickly discard most of the bogus cases
    if (mpz_probab_prime_p(gmpTarget, 1) == 0)
    {
        mpz_clear(gmpTarget);
        return error("CheckProofOfWork() : n not prime");
    }

    mpz_add_ui(gmpTarget, gmpTarget, 4);
    if (mpz_probab_prime_p(gmpTarget, 1) == 0)
    {
        mpz_clear(gmpTarget);
        return error("CheckProofOfWork() : n+4 not prime");
    }

    mpz_add_ui(gmpTarget, gmpTarget, 2);
    if (mpz_probab_prime_p(gmpTarget, 1) == 0)
    {
        mpz_clear(gmpTarget);
        return error("CheckProofOfWork() : n+6 not prime");
    }

    mpz_add_ui(gmpTarget, gmpTarget, 4);
    if (mpz_probab_prime_p(gmpTarget, 1) == 0)
    {
        mpz_clear(gmpTarget);
        return error("CheckProofOfWork() : n+10 not prime");
    }

    mpz_add_ui(gmpTarget, gmpTarget, 2);
    if (mpz_probab_prime_p(gmpTarget, 1) == 0)
    {
        mpz_clear(gmpTarget);
        return error("CheckProofOfWork() : n+12 not prime");
    }

    mpz_add_ui(gmpTarget, gmpTarget, 4);
    if (mpz_probab_prime_p(gmpTarget, 4) == 0)
    {
        mpz_clear(gmpTarget);
        return error("CheckProofOfWork() : n+16 not prime");
    }

    mpz_sub_ui(gmpTarget, gmpTarget, 4);
    if (mpz_probab_prime_p(gmpTarget, 3) == 0)
    {
        mpz_clear(gmpTarget);
        return error("CheckProofOfWork() : n+12 not prime");
    }

    mpz_sub_ui(gmpTarget, gmpTarget, 2);
    if (mpz_probab_prime_p(gmpTarget, 3) == 0)
    {
        mpz_clear(gmpTarget);
        return error("CheckProofOfWork() : n+10 not prime");
    }

    mpz_sub_ui(gmpTarget, gmpTarget, 4);
    if (mpz_probab_prime_p(gmpTarget, 3) == 0)
    {
        mpz_clear(gmpTarget);
        return error("CheckProofOfWork() : n+6 not prime");
    }

    mpz_sub_ui(gmpTarget, gmpTarget, 2);
    if (mpz_probab_prime_p(gmpTarget, 3) == 0)
    {
        mpz_clear(gmpTarget);
        return error("CheckProofOfWork() : n+4 not prime");
    }

    mpz_sub_ui(gmpTarget, gmpTarget, 4);
    if (mpz_probab_prime_p(gmpTarget, 3) == 0)
    {
        mpz_clear(gmpTarget);
        return error("CheckProofOfWork() : n not prime");
    }

    mpz_clear(gmpTarget);

    return true;
}

