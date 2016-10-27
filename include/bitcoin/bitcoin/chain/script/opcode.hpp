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
#ifndef LIBBITCOIN_CHAIN_OPCODE_HPP
#define LIBBITCOIN_CHAIN_OPCODE_HPP

#include <cstdint>
#include <string>
#include <bitcoin/bitcoin/define.hpp>
#include <bitcoin/bitcoin/utility/assert.hpp>
#include <bitcoin/bitcoin/utility/data.hpp>

namespace libbitcoin {
namespace chain {

// The 'ver' opcodes aren't in the main Satoshi EvalScript switch-case.
// So they are 'disabled' even though they are not listed in that code as such.
// We don't carry mnemonics for 'disabled' opcodes, as they are simply invalid.

enum class opcode : uint8_t
{
    //-------------------------------------------------------------------------
    // These are data.

    zero = 0,
    /* opcode::special range 1-76, wire opcodes but not internal opcodes */
    pushdata1 = 76,
    pushdata2 = 77,
    pushdata4 = 78,
    negative_1 = 79,
    positive_1 = 81,
    positive_2 = 82,
    positive_3 = 83,
    positive_4 = 84,
    positive_5 = 85,
    positive_6 = 86,
    positive_7 = 87,
    positive_8 = 88,
    positive_9 = 89,
    positive_10 = 90,
    positive_11 = 91,
    positive_12 = 92,
    positive_13 = 93,
    positive_14 = 94,
    positive_15 = 95,
    positive_16 = 96,

    //-------------------------------------------------------------------------
    // These are executable.

    nop = 97,
    disabled_98 = 98,
    if_ = 99,
    notif = 100,
    disabled_101 = 101,
    disabled_102 = 102,
    else_ = 103,
    endif = 104,
    verify = 105,
    return_ = 106,
    toaltstack = 107,
    fromaltstack = 108,
    drop2 = 109,
    dup2 = 110,
    dup3 = 111,
    over2 = 112,
    rot2 = 113,
    swap2 = 114,
    ifdup = 115,
    depth = 116,
    drop = 117,
    dup = 118,
    nip = 119,
    over = 120,
    pick = 121,
    roll = 122,
    rot = 123,
    swap = 124,
    tuck = 125,
    disabled_126 = 126,
    disabled_127 = 127,
    disabled_128 = 128,
    disabled_129 = 129,
    size = 130,
    disabled_131 = 131,
    disabled_132 = 132,
    disabled_133 = 133,
    disabled_134 = 134,
    equal = 135,
    equalverify = 136,
    disabled_137 = 137,
    disabled_138 = 138,
    add1 = 139,
    sub1 = 140,
    disabled_141 = 141,
    disabled_142 = 142,
    negate = 143,
    abs = 144,
    not_ = 145,
    nonzero = 146,
    add = 147,
    sub = 148,
    disabled_149 = 149,
    disabled_150 = 150,
    disabled_151 = 151,
    disabled_152 = 152,
    disabled_153 = 153,
    booland = 154,
    boolor = 155,
    numequal = 156,
    numequalverify = 157,
    numnotequal = 158,
    lessthan = 159,
    greaterthan = 160,
    lessthanorequal = 161,
    greaterthanorequal = 162,
    min = 163,
    max = 164,
    within = 165,
    ripemd160 = 166,
    sha1 = 167,
    sha256 = 168,
    hash160 = 169,
    hash256 = 170,
    codeseparator = 171,
    checksig = 172,
    checksigverify = 173,
    checkmultisig = 174,
    checkmultisigverify = 175,
    nop1 = 176,
    nop2 = 177,
    checklocktimeverify = nop2,
    nop3 = 178,
    nop4 = 179,
    nop5 = 180,
    nop6 = 181,
    nop7 = 182,
    nop8 = 183,
    nop9 = 184,
    nop10 = 185,

    //-------------------------------------------------------------------------
    // These are sentinels (values are arbitry).

    bad_operation,
    special,
    raw_data
};

/// Convert the opcode to a mnemonic string.
BC_API std::string opcode_to_string(opcode value, uint32_t flags);

/// Convert a string to an opcode.
BC_API opcode opcode_from_string(const std::string& value);

} // namespace chain
} // namespace libbitcoin

#endif
