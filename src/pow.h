// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Riecoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_H
#define BITCOIN_POW_H

#include <consensus/params.h>

#include <stdint.h>
#include "primitives/block.h"
#include <gmp.h>

class CBlockHeader;
class CBlockIndex;
class uint256;

const int RIECOIN_CONSTELLATION_SIZE = 6;
const int ZEROS_BEFORE_HASH_IN_PRIME = 8;
const int RIECOIN_MIN_PRIME_SIZE     = 304; // this results in primes of size 1+8 (ZEROS_BEFORE_HASH_IN_PRIME)+256 (hash)+39 = 304 bits

bool isAfterFork1(int nHeight, const Consensus::Params& params);
bool isInSuperblockInterval(int nHeight, const Consensus::Params& params);
bool isSuperblock(int nHeight, const Consensus::Params& params);

unsigned int generatePrimeBase(mpz_t gmpTarget, uint256 hash, bitsType compactBits);
unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params&);
unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params&);

/** Check whether a block hash satisfies the proof-of-work requirement specified by nBits */
bool CheckProofOfWork(uint256 hash, bitsType nBits, offsetType delta, const Consensus::Params&);

#endif // BITCOIN_POW_H
