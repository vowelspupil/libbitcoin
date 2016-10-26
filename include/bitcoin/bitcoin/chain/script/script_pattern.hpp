/**
 * Copyright (c) 2011-2015 libbitcoin developers (see AUTHORS)
 *
 * This file is part of libbitcoin.
 *
 * libbitcoin is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License with
 * additional permissions to the one published by the Free Software
 * Foundation, either version 3 of the License, or (at your option)
 * any later version. For more information see LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef LIBBITCOIN_CHAIN_SCRIPT_PATTERN_HPP
#define LIBBITCOIN_CHAIN_SCRIPT_PATTERN_HPP

namespace libbitcoin {
namespace chain {

/// Script patterms.
/// Comments from: bitcoin.org/en/developer-guide#signature-hash-types
enum class script_pattern
{
    /// Null Data
    /// Pubkey Script: OP_RETURN <0 to 80 bytes of data> (formerly 40 bytes)
    /// Null data scripts cannot be spent, so there's no signature script.
    null_data,

    /// Pay to Multisig [BIP11]
    /// Pubkey script: <m> <A pubkey>[B pubkey][C pubkey...] <n> OP_CHECKMULTISIG
    /// Signature script: OP_0 <A sig>[B sig][C sig...]
    pay_multisig,

    /// Pay to Public Key (obsolete)
    pay_public_key,

    /// Pay to Public Key Hash [P2PKH]
    /// Pubkey script: OP_DUP OP_HASH160 <PubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
    /// Signature script: <sig> <pubkey>
    pay_key_hash,

    /// Pay to Script Hash [P2SH/BIP16]
    /// The redeem script may be any pay type, but only multisig makes sense.
    /// Pubkey script: OP_HASH160 <Hash160(redeemScript)> OP_EQUAL
    /// Signature script: <sig>[sig][sig...] <redeemScript>
    pay_script_hash,

    /// Sign Multisig script [BIP11]
    sign_multisig,

    /// Sign Public Key (obsolete)
    sign_public_key,

    /// Sign Public Key Hash [P2PKH]
    sign_key_hash,

    /// Sign Script Hash [P2SH/BIP16]
    sign_script_hash,

    /// The script is valid but does not conform to the standard templates.
    /// Such scripts are always accepted if they are mined into blocks, but
    /// transactions with non-standard scripts may not be forwarded by peers.
    non_standard
};

} // end chain
} // end libbitcoin

#endif
