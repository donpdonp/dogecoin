#!/usr/bin/env python3
# Copyright (c) 2015-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Utilities for manipulating blocks and transactions."""

from .mininode import *
from .script import CScript, OP_TRUE, OP_CHECKSIG, OP_RETURN

# Create a block (with regtest difficulty)
def create_block(hashprev, coinbase, nTime=None, nBits=0x207fffff):
    block = CBlock()
    # Dogecoin: Create a non-AuxPoW block but include chain ID
    block.nVersion = 0x620003
    if nTime is None:
        import time
        block.nTime = int(time.time()+600)
    else:
        block.nTime = nTime
    block.hashPrevBlock = hashprev
    block.nBits = nBits
    block.vtx.append(coinbase)
    block.hashMerkleRoot = block.calc_merkle_root()
    block.calc_sha256()
    return block

# From BIP141
WITNESS_COMMITMENT_HEADER = b"\xaa\x21\xa9\xed"

def dogecoinNextWorkRequired(tip, tip_prev, height):
    spacing_timespan = 5 # nPowTargetSpacing
    digishield = height >= 10 # digishieldConsensus.nHeightEffective = 10
    actual_timespan = tip.nTime - tip_prev.nTime
    if digishield:
        retarget_timespan = spacing_timespan # digishieldConsensus.nPowTargetTimespan
        timespan_diff = actual_timespan - retarget_timespan
        modulated_timespan = retarget_timespan + python_division_negative_roundup(timespan_diff, 8)
        min_timespan = retarget_timespan - (retarget_timespan // 4)
        max_timespan = retarget_timespan + (retarget_timespan // 2)
    else:
        retarget_timespan = 4 * 60 * 60 # nPowTargetTimespan
        modulated_timespan = actual_timespan
        min_timespan = retarget_timespan // 16
        max_timespan = retarget_timespan * 4

    if height % (retarget_timespan // spacing_timespan) != 0:
        return tip.nBits

    if modulated_timespan < min_timespan:
        modulated_timespan = min_timespan
    elif modulated_timespan > max_timespan:
        modulated_timespan = max_timespan

    bnNew = uint256_from_compact(tip.nBits)
    # dogecoin.cpp: bnNew *= nModulatedTimespan;
    bnNew *= modulated_timespan
    # dogecoin.cpp: bnNew /= retargetTimespan;
    bnNew //= retarget_timespan

    return uint256_to_compact(bnNew)

def python_division_negative_roundup(numerator, divisor):
    if (numerator < 0) and (numerator % divisor != 0):
        python_floor_divison_offset = 1
    else:
        python_floor_divison_offset = 0
    return numerator // divisor + python_floor_divison_offset

def get_witness_script(witness_root, witness_nonce):
    witness_commitment = uint256_from_str(hash256(ser_uint256(witness_root)+ser_uint256(witness_nonce)))
    output_data = WITNESS_COMMITMENT_HEADER + ser_uint256(witness_commitment)
    return CScript([OP_RETURN, output_data])


# According to BIP141, blocks with witness rules active must commit to the
# hash of all in-block transactions including witness.
def add_witness_commitment(block, nonce=0):
    # First calculate the merkle root of the block's
    # transactions, with witnesses.
    witness_nonce = nonce
    witness_root = block.calc_witness_merkle_root()
    # witness_nonce should go to coinbase witness.
    block.vtx[0].wit.vtxinwit = [CTxInWitness()]
    block.vtx[0].wit.vtxinwit[0].scriptWitness.stack = [ser_uint256(witness_nonce)]

    # witness commitment is the last OP_RETURN output in coinbase
    block.vtx[0].vout.append(CTxOut(0, get_witness_script(witness_root, witness_nonce)))
    block.vtx[0].rehash()
    block.hashMerkleRoot = block.calc_merkle_root()
    block.rehash()


def serialize_script_num(value):
    r = bytearray(0)
    if value == 0:
        return r
    neg = value < 0
    absvalue = -value if neg else value
    while (absvalue):
        r.append(int(absvalue & 0xff))
        absvalue >>= 8
    if r[-1] & 0x80:
        r.append(0x80 if neg else 0)
    elif neg:
        r[-1] |= 0x80
    return r

# Create a coinbase transaction, assuming no miner fees.
# If pubkey is passed in, the coinbase output will be a P2PK output;
# otherwise an anyone-can-spend output.
def create_coinbase(height, pubkey = None):
    coinbase = CTransaction()
    coinbase.vin.append(CTxIn(COutPoint(0, 0xffffffff),
                ser_string(serialize_script_num(height)), 0xffffffff))
    coinbaseoutput = CTxOut()
    coinbaseoutput.nValue = 500000 * COIN
    halvings = int(height/150) # regtest
    coinbaseoutput.nValue >>= halvings
    if (pubkey != None):
        coinbaseoutput.scriptPubKey = CScript([pubkey, OP_CHECKSIG])
    else:
        coinbaseoutput.scriptPubKey = CScript([OP_TRUE])
    coinbase.vout = [ coinbaseoutput ]
    coinbase.calc_sha256()
    return coinbase

# Create a transaction.
# If the scriptPubKey is not specified, make it anyone-can-spend.
def create_transaction(prevtx, n, sig, value, scriptPubKey=CScript()):
    tx = CTransaction()
    assert(n < len(prevtx.vout))
    tx.vin.append(CTxIn(COutPoint(prevtx.sha256, n), sig, 0xffffffff))
    tx.vout.append(CTxOut(value, scriptPubKey))
    tx.calc_sha256()
    return tx

def get_legacy_sigopcount_block(block, fAccurate=True):
    count = 0
    for tx in block.vtx:
        count += get_legacy_sigopcount_tx(tx, fAccurate)
    return count

def get_legacy_sigopcount_tx(tx, fAccurate=True):
    count = 0
    for i in tx.vout:
        count += i.scriptPubKey.GetSigOpCount(fAccurate)
    for j in tx.vin:
        # scriptSig might be of type bytes, so convert to CScript for the moment
        count += CScript(j.scriptSig).GetSigOpCount(fAccurate)
    return count
