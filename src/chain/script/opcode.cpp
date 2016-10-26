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
#include <bitcoin/bitcoin/chain/script/opcode.hpp>

#include <sstream>
#include <bitcoin/bitcoin/constants.hpp>

namespace libbitcoin {
namespace chain {

std::string opcode_to_string(opcode value, uint32_t flags)
{
    switch (value)
    {
        case opcode::zero:
            return "zero";
        case opcode::special:
            return "special";
        case opcode::pushdata1:
            return "pushdata1";
        case opcode::pushdata2:
            return "pushdata2";
        case opcode::pushdata4:
            return "pushdata4";
        case opcode::negative_1:
            return "-1";
        case opcode::op_1:
            return "1";
        case opcode::op_2:
            return "2";
        case opcode::op_3:
            return "3";
        case opcode::op_4:
            return "4";
        case opcode::op_5:
            return "5";
        case opcode::op_6:
            return "6";
        case opcode::op_7:
            return "7";
        case opcode::op_8:
            return "8";
        case opcode::op_9:
            return "9";
        case opcode::op_10:
            return "10";
        case opcode::op_11:
            return "11";
        case opcode::op_12:
            return "12";
        case opcode::op_13:
            return "13";
        case opcode::op_14:
            return "14";
        case opcode::op_15:
            return "15";
        case opcode::op_16:
            return "16";
        case opcode::nop:
            return "nop";
        case opcode::if_:
            return "if";
        case opcode::notif:
            return "notif";
        case opcode::else_:
            return "else";
        case opcode::endif:
            return "endif";
        case opcode::verify:
            return "verify";
        case opcode::return_:
            return "return";
        case opcode::toaltstack:
            return "toaltstack";
        case opcode::fromaltstack:
            return "fromaltstack";
        case opcode::drop2:
            return "drop2";
        case opcode::dup2:
            return "dup2";
        case opcode::dup3:
            return "dup3";
        case opcode::over2:
            return "over2";
        case opcode::rot2:
            return "rot2";
        case opcode::swap2:
            return "swap2";
        case opcode::ifdup:
            return "ifdup";
        case opcode::depth:
            return "depth";
        case opcode::drop:
            return "drop";
        case opcode::dup:
            return "dup";
        case opcode::nip:
            return "nip";
        case opcode::over:
            return "over";
        case opcode::pick:
            return "pick";
        case opcode::roll:
            return "roll";
        case opcode::rot:
            return "rot";
        case opcode::swap:
            return "swap";
        case opcode::tuck:
            return "tuck";
        case opcode::size:
            return "size";
        case opcode::equal:
            return "equal";
        case opcode::equalverify:
            return "equalverify";
        case opcode::add1:
            return "add1";
        case opcode::sub1:
            return "sub1";
        case opcode::negate:
            return "negate";
        case opcode::abs:
            return "abs";
        case opcode::not_:
            return "not";
        case opcode::nonzero:
            return "nonzero";
        case opcode::add:
            return "add";
        case opcode::sub:
            return "sub";
        case opcode::booland:
            return "booland";
        case opcode::boolor:
            return "boolor";
        case opcode::numequal:
            return "numequal";
        case opcode::numequalverify:
            return "numequalverify";
        case opcode::numnotequal:
            return "numnotequal";
        case opcode::lessthan:
            return "lessthan";
        case opcode::greaterthan:
            return "greaterthan";
        case opcode::lessthanorequal:
            return "lessthanorequal";
        case opcode::greaterthanorequal:
            return "greaterthanorequal";
        case opcode::min:
            return "min";
        case opcode::max:
            return "max";
        case opcode::within:
            return "within";
        case opcode::ripemd160:
            return "ripemd160";
        case opcode::sha1:
            return "sha1";
        case opcode::sha256:
            return "sha256";
        case opcode::hash160:
            return "hash160";
        case opcode::hash256:
            return "hash256";
        case opcode::codeseparator:
            return "codeseparator";
        case opcode::checksig:
            return "checksig";
        case opcode::checksigverify:
            return "checksigverify";
        case opcode::checkmultisig:
            return "checkmultisig";
        case opcode::checkmultisigverify:
            return "checkmultisigverify";
        case opcode::nop1:
            return "nop1";
        case opcode::nop2:
            return "nop2";
        case opcode::nop3:
            return "nop3";
        case opcode::nop4:
            return "nop4";
        case opcode::nop5:
            return "nop5";
        case opcode::nop6:
            return "nop6";
        case opcode::nop7:
            return "nop7";
        case opcode::nop8:
            return "nop8";
        case opcode::nop9:
            return "nop9";
        case opcode::nop10:
            return "nop10";
        case opcode::raw_data:
            return "raw_data";
        case opcode::bad_operation:
        default:
        {
            std::ostringstream ss;
            ss << "<" << static_cast<uint16_t>(value) << ">";
            return ss.str();
        }
    }
}

opcode opcode_from_string(const std::string& value)
{
    if (value == "zero")
        return opcode::zero;
    if (value == "special")
        return opcode::special;
    if (value == "pushdata1")
        return opcode::pushdata1;
    if (value == "pushdata2")
        return opcode::pushdata2;
    if (value == "pushdata4")
        return opcode::pushdata4;
    if (value == "-1")
        return opcode::negative_1;
    if (value == "1")
        return opcode::op_1;
    if (value == "2")
        return opcode::op_2;
    if (value == "3")
        return opcode::op_3;
    if (value == "4")
        return opcode::op_4;
    if (value == "5")
        return opcode::op_5;
    if (value == "6")
        return opcode::op_6;
    if (value == "7")
        return opcode::op_7;
    if (value == "8")
        return opcode::op_8;
    if (value == "9")
        return opcode::op_9;
    if (value == "10")
        return opcode::op_10;
    if (value == "11")
        return opcode::op_11;
    if (value == "12")
        return opcode::op_12;
    if (value == "13")
        return opcode::op_13;
    if (value == "14")
        return opcode::op_14;
    if (value == "15")
        return opcode::op_15;
    if (value == "16")
        return opcode::op_16;
    if (value == "nop")
        return opcode::nop;
    if (value == "if")
        return opcode::if_;
    if (value == "notif")
        return opcode::notif;
    if (value == "else")
        return opcode::else_;
    if (value == "endif")
        return opcode::endif;
    if (value == "verify")
        return opcode::verify;
    if (value == "return")
        return opcode::return_;
    if (value == "toaltstack")
        return opcode::toaltstack;
    if (value == "fromaltstack")
        return opcode::fromaltstack;
    if (value == "drop2")
        return opcode::drop2;
    if (value == "dup2")
        return opcode::dup2;
    if (value == "dup3")
        return opcode::dup3;
    if (value == "over2")
        return opcode::over2;
    if (value == "rot2")
        return opcode::rot2;
    if (value == "swap2")
        return opcode::swap2;
    if (value == "ifdup")
        return opcode::ifdup;
    if (value == "depth")
        return opcode::depth;
    if (value == "drop")
        return opcode::drop;
    if (value == "dup")
        return opcode::dup;
    if (value == "nip")
        return opcode::nip;
    if (value == "over")
        return opcode::over;
    if (value == "pick")
        return opcode::pick;
    if (value == "roll")
        return opcode::roll;
    if (value == "rot")
        return opcode::rot;
    if (value == "swap")
        return opcode::swap;
    if (value == "tuck")
        return opcode::tuck;
    if (value == "size")
        return opcode::size;
    if (value == "equal")
        return opcode::equal;
    if (value == "equalverify")
        return opcode::equalverify;
    if (value == "add1")
        return opcode::add1;
    if (value == "sub1")
        return opcode::sub1;
    if (value == "negate")
        return opcode::negate;
    if (value == "abs")
        return opcode::abs;
    if (value == "not")
        return opcode::not_;
    if (value == "nonzero")
        return opcode::nonzero;
    if (value == "add")
        return opcode::add;
    if (value == "sub")
        return opcode::sub;
    if (value == "booland")
        return opcode::booland;
    if (value == "boolor")
        return opcode::boolor;
    if (value == "numequal")
        return opcode::numequal;
    if (value == "numequalverify")
        return opcode::numequalverify;
    if (value == "numnotequal")
        return opcode::numnotequal;
    if (value == "lessthan")
        return opcode::lessthan;
    if (value == "greaterthan")
        return opcode::greaterthan;
    if (value == "lessthanorequal")
        return opcode::lessthanorequal;
    if (value == "greaterthanorequal")
        return opcode::greaterthanorequal;
    if (value == "min")
        return opcode::min;
    if (value == "max")
        return opcode::max;
    if (value == "within")
        return opcode::within;
    if (value == "ripemd160")
        return opcode::ripemd160;
    if (value == "sha1")
        return opcode::sha1;
    if (value == "sha256")
        return opcode::sha256;
    if (value == "hash160")
        return opcode::hash160;
    if (value == "hash256")
        return opcode::hash256;
    if (value == "codeseparator")
        return opcode::codeseparator;
    if (value == "checksig")
        return opcode::checksig;
    if (value == "checksigverify")
        return opcode::checksigverify;
    if (value == "checkmultisig")
        return opcode::checkmultisig;
    if (value == "checkmultisigverify")
        return opcode::checkmultisigverify;
    if (value == "checklocktimeverify")
        return opcode::checklocktimeverify;
    if (value == "nop1")
        return opcode::nop1;
    if (value == "nop2")
        return opcode::nop2;
    if (value == "nop3")
        return opcode::nop3;
    if (value == "nop4")
        return opcode::nop4;
    if (value == "nop5")
        return opcode::nop5;
    if (value == "nop6")
        return opcode::nop6;
    if (value == "nop7")
        return opcode::nop7;
    if (value == "nop8")
        return opcode::nop8;
    if (value == "nop9")
        return opcode::nop9;
    if (value == "nop10")
        return opcode::nop10;
    if (value == "raw_data")
        return opcode::raw_data;

    return opcode::bad_operation;
}

} // namespace chain
} // namespace libbitcoin
