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
#include <bitcoin/bitcoin/chain/script/interpreter.hpp>

#include <cstddef>
#include <cstdint>
#include <iterator>
#include <utility>
#include <bitcoin/bitcoin/constants.hpp>
#include <bitcoin/bitcoin/chain/script/evaluation_context.hpp>
#include <bitcoin/bitcoin/chain/script/opcode.hpp>
#include <bitcoin/bitcoin/chain/script/operation.hpp>
#include <bitcoin/bitcoin/chain/script/rule_fork.hpp>
#include <bitcoin/bitcoin/chain/script/sighash_algorithm.hpp>
#include <bitcoin/bitcoin/chain/transaction.hpp>
#include <bitcoin/bitcoin/error.hpp>
#include <bitcoin/bitcoin/math/elliptic_curve.hpp>
#include <bitcoin/bitcoin/math/hash.hpp>
#include <bitcoin/bitcoin/math/script_number.hpp>
#include <bitcoin/bitcoin/utility/assert.hpp>

namespace libbitcoin {
namespace chain {
    
enum class signature_parse_result
{
    valid,
    invalid,
    lax_encoding
};

// Operations.
//-----------------------------------------------------------------------------
// shared handler
static bool op_disabled(opcode)
{
    BITCOIN_ASSERT_MSG(false, "disabled opcode in run");
    return false;
}

// shared handler
static bool op_reserved(opcode)
{
    return false;
}

// shared handler
static bool op_nop(opcode)
{
    return true;
}

// shared handler
static bool op_push_size(evaluation_context& context, const operation& op)
{
    static constexpr auto op_75 = static_cast<uint8_t>(opcode::push_size_75);
    const auto size = op.code();
    BITCOIN_ASSERT(op.data().size() <= op_75);
    context.stack.push_back(op.data());
    return true;
}

// shared handler
static bool op_push_size(evaluation_context& context, const data_chunk& data,
    uint32_t DEBUG_ONLY(size_limit))
{
    BITCOIN_ASSERT(data.size() <= size_limit);
    context.stack.push_back(data);
    return true;
}

// shared handler
static bool op_push_number(evaluation_context& context, uint8_t value)
{
    // This handles positive_0 identically to op_push_size with empty data.
    BITCOIN_ASSERT(value == script_number::negative_1 || 
        value <= script_number::positive_16);
    context.stack.push_back({ value });
    return true;
}

static bool op_if(evaluation_context& context)
{
    auto value = false;

    if (context.condition.succeeded())
    {
        if (context.stack.empty())
            return false;

        value = context.stack_state();
        context.pop();
    }

    context.condition.open(value);
    return true;
}

static bool op_notif(evaluation_context& context)
{
    auto value = false;

    if (context.condition.succeeded())
    {
        if (context.stack.empty())
            return false;

        value = !context.stack_state();
        context.pop();
    }

    context.condition.open(value);
    return true;
}

static bool op_else(evaluation_context& context)
{
    if (context.condition.closed())
        return false;

    context.condition.negate();
    return true;
}

static bool op_endif(evaluation_context& context)
{
    if (context.condition.closed())
        return false;

    context.condition.close();
    return true;
}

static bool op_verify(evaluation_context& context)
{
    if (context.stack.empty())
        return false;

    if (!context.stack_state())
        return false;

    context.pop();
    return true;
}

static bool op_return(evaluation_context& context)
{
    // In terms of validation op_return behaves identical to reserved opcodes.
    return false;
}

static bool op_to_alt_stack(evaluation_context& context)
{
    if (context.stack.empty())
        return false;

    context.alternate.push_back(context.pop());
    return true;
}

static bool op_from_alt_stack(evaluation_context& context)
{
    if (context.alternate.empty())
        return false;

    context.stack.push_back(context.alternate.back());
    context.alternate.pop_back();
    return true;
}

static bool op_drop2(evaluation_context& context)
{
    if (context.stack.size() < 2)
        return false;

    context.stack.pop_back();
    context.stack.pop_back();
    return true;
}

static bool op_dup2(evaluation_context& context)
{
    if (context.stack.size() < 2)
        return false;

    auto item1 = context.item(1);
    auto item0 = context.item(0);

    context.stack.emplace_back(std::move(item1));
    context.stack.emplace_back(std::move(item0));
    return true;
}

static bool op_dup3(evaluation_context& context)
{
    if (context.stack.size() < 3)
        return false;

    auto item2 = context.item(2);
    auto item1 = context.item(1);
    auto item0 = context.item(0);

    context.stack.emplace_back(std::move(item2));
    context.stack.emplace_back(std::move(item1));
    context.stack.emplace_back(std::move(item0));
    return true;
}

static bool op_over2(evaluation_context& context)
{
    if (context.stack.size() < 4)
        return false;

    auto item3 = context.item(3);
    auto item2 = context.item(2);

    context.stack.emplace_back(std::move(item3));
    context.stack.emplace_back(std::move(item2));
    return true;
}

static bool op_rot2(evaluation_context& context)
{
    if (context.stack.size() < 6)
        return false;

    const auto position_5 = context.position(5);
    const auto position_4 = context.position(4);

    auto copy_5 = *position_5;
    auto copy_4 = *position_4;

    context.stack.erase(position_5, position_4 + 1);
    context.stack.emplace_back(std::move(copy_5));
    context.stack.emplace_back(std::move(copy_4));
    return true;
}

static bool op_swap2(evaluation_context& context)
{
    if (context.stack.size() < 4)
        return false;

    context.swap(3, 1);
    context.swap(2, 0);
    return true;
}

static bool op_if_dup(evaluation_context& context)
{
    if (context.stack.empty())
        return false;

    if (context.stack_state())
        context.duplicate(0);

    return true;
}

static bool op_depth(evaluation_context& context)
{
    //*************************************************************************
    // CONSENSUS: overflow potential (size_t > max_uint64).
    //*************************************************************************
    const script_number stack_size(context.stack.size());
    context.stack.push_back(stack_size.data());
    return true;
}

static bool op_drop(evaluation_context& context)
{
    if (context.stack.empty())
        return false;

    context.pop();
    return true;
}

static bool op_dup(evaluation_context& context)
{
    if (context.stack.empty())
        return false;

    context.duplicate(0);
    return true;
}

static bool op_nip(evaluation_context& context)
{
    if (context.stack.size() < 2)
        return false;

    context.stack.erase(context.position(1));
    return true;
}

static bool op_over(evaluation_context& context)
{
    if (context.stack.size() < 2)
        return false;

    context.duplicate(1);
    return true;
}

static bool op_pick(evaluation_context& context)
{
    data_stack::iterator position;
    if (!context.pop_position(position))
        return false;

    context.stack.push_back(*position);
    return true;
}

static bool op_roll(evaluation_context& context)
{
    data_stack::iterator position;
    if (!context.pop_position(position))
        return false;

    auto copy = *position;
    context.stack.erase(position);
    context.stack.emplace_back(std::move(copy));
    return true;
}

static bool op_rot(evaluation_context& context)
{
    if (context.stack.size() < 3)
        return false;

    context.swap(2, 1);
    context.swap(1, 0);
    return true;
}

static bool op_swap(evaluation_context& context)
{
    if (context.stack.size() < 2)
        return false;

    context.swap(1, 0);
    return true;
}

static bool op_tuck(evaluation_context& context)
{
    if (context.stack.size() < 2)
        return false;

    context.stack.insert(context.position(1), context.stack.back());
    return true;
}

static bool op_size(evaluation_context& context)
{
    if (context.stack.empty())
        return false;

    //*************************************************************************
    // CONSENSUS: overflow potential (size_t > max_uint64).
    //*************************************************************************
    const script_number top_size(context.stack.back().size());
    context.stack.push_back(top_size.data());
    return true;
}

static bool op_equal(evaluation_context& context)
{
    if (context.stack.size() < 2)
        return false;

    context.push(context.pop() == context.pop());
    return true;
}

static bool op_equal_verify(evaluation_context& context)
{
    if (context.stack.size() < 2)
        return false;

    return context.pop() == context.pop();
}

static bool op_add1(evaluation_context& context)
{
    script_number number;
    if (!context.pop(number))
        return false;

    //*************************************************************************
    // CONSENSUS: overflow potential.
    //*************************************************************************
    number += 1;
    context.stack.push_back(number.data());
    return true;
}

static bool op_sub1(evaluation_context& context)
{
    script_number number;
    if (!context.pop(number))
        return false;

    //*************************************************************************
    // CONSENSUS: underflow potential.
    //*************************************************************************
    number -= 1;
    context.stack.push_back(number.data());
    return true;
}

static bool op_negate(evaluation_context& context)
{
    script_number number;
    if (!context.pop(number))
        return false;

    //*************************************************************************
    // CONSENSUS: overflow potential.
    //*************************************************************************
    number = -number;
    context.stack.push_back(number.data());
    return true;
}

static bool op_abs(evaluation_context& context)
{
    script_number number;
    if (!context.pop(number))
        return false;

    //*************************************************************************
    // CONSENSUS: overflow potential.
    //*************************************************************************
    if (number < 0)
        number = -number;

    context.stack.push_back(number.data());
    return true;
}

static bool op_not(evaluation_context& context)
{
    script_number number;
    if (!context.pop(number))
        return false;

    context.push(number == 0);
    return true;
}

static bool op_nonzero(evaluation_context& context)
{
    script_number number;
    if (!context.pop(number))
        return false;

    context.push(number != 0);
    return true;
}

static bool op_add(evaluation_context& context)
{
    script_number first, second;
    if (!context.pop_binary(first, second))
        return false;

    //*************************************************************************
    // CONSENSUS: overflow potential.
    //*************************************************************************
    const auto result = first + second;
    context.stack.push_back(result.data());
    return true;
}

static bool op_sub(evaluation_context& context)
{
    script_number first, second;
    if (!context.pop_binary(first, second))
        return false;

    //*************************************************************************
    // CONSENSUS: underflow potential.
    //*************************************************************************
    const auto result = second - first;
    context.stack.push_back(result.data());
    return true;
}

static bool op_bool_and(evaluation_context& context)
{
    script_number first, second;
    if (!context.pop_binary(first, second))
        return false;

    context.push(first != 0 && second != 0);
    return true;
}

static bool op_bool_or(evaluation_context& context)
{
    script_number first, second;
    if (!context.pop_binary(first, second))
        return false;

    context.push(first != 0 || second != 0);
    return true;
}

static bool op_num_equal(evaluation_context& context)
{
    script_number first, second;
    if (!context.pop_binary(first, second))
        return false;

    context.push(first == second);
    return true;
}

static bool op_num_equal_verify(evaluation_context& context)
{
    script_number first, second;
    if (!context.pop_binary(first, second))
        return false;

    return first == second;
}

static bool op_num_not_equal(evaluation_context& context)
{
    script_number first, second;
    if (!context.pop_binary(first, second))
        return false;

    context.push(first != second);
    return true;
}

static bool op_less_than(evaluation_context& context)
{
    script_number first, second;
    if (!context.pop_binary(first, second))
        return false;

    context.push(second < first);
    return true;
}

static bool op_greater_than(evaluation_context& context)
{
    script_number first, second;
    if (!context.pop_binary(first, second))
        return false;

    context.push(second > first);
    return true;
}

static bool op_less_than_or_equal(evaluation_context& context)
{
    script_number first, second;
    if (!context.pop_binary(first, second))
        return false;

    context.push(second <= first);
    return true;
}

static bool op_greater_than_or_equal(evaluation_context& context)
{
    script_number first, second;
    if (!context.pop_binary(first, second))
        return false;

    context.push(second >= first);
    return true;
}

static bool op_min(evaluation_context& context)
{
    script_number first, second;
    if (!context.pop_binary(first, second))
        return false;

    if (second < first)
        context.stack.push_back(second.data());
    else
        context.stack.push_back(first.data());

    return true;
}

static bool op_max(evaluation_context& context)
{
    script_number first, second;
    if (!context.pop_binary(first, second))
        return false;

    auto greater = second > first ? second.data() : first.data();
    context.stack.emplace_back(std::move(greater));
    return true;
}

static bool op_within(evaluation_context& context)
{
    script_number first, second, third;
    if (!context.pop_ternary(first, second, third))
        return false;

    context.push(second <= third && third < first);
    return true;
}

static bool op_ripemd160(evaluation_context& context)
{
    if (context.stack.empty())
        return false;

    // TODO: move buffer.
    const auto hash = ripemd160_hash(context.pop());
    context.stack.push_back(to_chunk(hash));
    return true;
}

static bool op_sha1(evaluation_context& context)
{
    if (context.stack.empty())
        return false;

    // TODO: move buffer.
    context.stack.push_back(to_chunk(sha1_hash(context.pop())));
    return true;
}

static bool op_sha256(evaluation_context& context)
{
    if (context.stack.empty())
        return false;

    // TODO: move buffer.
    context.stack.push_back(to_chunk(sha256_hash(context.pop())));
    return true;
}

static bool op_hash160(evaluation_context& context)
{
    if (context.stack.empty())
        return false;

    // TODO: move buffer.
    context.stack.push_back(to_chunk(bitcoin_short_hash(context.pop())));
    return true;
}

static bool op_hash256(evaluation_context& context)
{
    if (context.stack.empty())
        return false;

    // TODO: move buffer.
    context.stack.push_back(to_chunk(bitcoin_hash(context.pop())));
    return true;
}

static bool op_code_seperator(evaluation_context& context,
    const operation::const_iterator op)
{
    // Modify context.begin() for the next op_check_[multi_]sig_verify call.
    context.reset(op + 1);
    return true;
}

static signature_parse_result op_check_sig_verify(evaluation_context& context,
    const script& script, const transaction& tx, uint32_t input_index)
{
    if (context.stack.size() < 2)
        return signature_parse_result::invalid;

    const auto pubkey = context.pop();
    auto endorsement = context.pop();

    if (endorsement.empty())
        return signature_parse_result::invalid;

    auto strict = script::is_enabled(context.flags(), rule_fork::bip66_rule);
    const auto sighash_type = endorsement.back();
    auto& distinguished = endorsement;
    distinguished.pop_back();
    ec_signature signature;
    operation_stack ops;

    if (strict && !parse_signature(signature, distinguished, true))
        return signature_parse_result::lax_encoding;

    if (!strict && !parse_signature(signature, distinguished, false))
        return signature_parse_result::invalid;

    //*************************************************************************
    // CONSENSUS: Satoshi has self-modifying code bug in FindAndDelete here.
    //*************************************************************************
    for (auto op = context.begin(); op != context.end(); ++op)
        if (op->data() != endorsement)
            ops.push_back(*op);

    const chain::script script_code(std::move(ops));
    return script::check_signature(signature, sighash_type, pubkey,
        script_code, tx, input_index) ? signature_parse_result::valid :
        signature_parse_result::invalid;
}

static bool op_check_sig(evaluation_context& context, const script& script,
    const transaction& tx, uint32_t input_index)
{
    switch (op_check_sig_verify(context, script, tx, input_index))
    {
        case signature_parse_result::valid:
            context.push(true);
            break;
        case signature_parse_result::invalid:
            context.push(false);
            break;
        case signature_parse_result::lax_encoding:
            return false;
    }

    return true;
}

static signature_parse_result op_check_multisig_verify(
    evaluation_context& context, const script& script, const transaction& tx,
    uint32_t input_index)
{
    int32_t pubkeys_count;
    if (!context.pop(pubkeys_count))
        return signature_parse_result::invalid;

    if (!context.update_pubkey_count(pubkeys_count))
        return signature_parse_result::invalid;

    data_stack pubkeys;
    if (!context.pop(pubkeys, pubkeys_count))
        return signature_parse_result::invalid;

    int32_t sigs_count;
    if (!context.pop(sigs_count))
        return signature_parse_result::invalid;

    if (sigs_count < 0 || sigs_count > pubkeys_count)
        return signature_parse_result::invalid;

    data_stack sigs;
    if (!context.pop(sigs, sigs_count))
        return signature_parse_result::invalid;

    if (context.stack.empty())
        return signature_parse_result::invalid;

    // Due to a bug in bitcoind, read and discard an extra op/byte.
    context.stack.pop_back();
    operation_stack ops;

    const auto is_endorsement = [&sigs](const data_chunk& data)
    {
        return std::find(sigs.begin(), sigs.end(), data) != sigs.end();
    };

    //*************************************************************************
    // CONSENSUS: Satoshi has a bug in FindAndDelete that we do not reproduce.
    // Its endorsement removal will strip matching operations, not just data.
    //*************************************************************************
    for (auto op = context.begin(); op != context.end(); ++op)
        if (!is_endorsement(op->data()))
            ops.push_back(*op);

    // The exact number of signatures are required and must be in order.
    // One key can validate more than one script. So we always advance 
    // until we exhaust either pubkeys (fail) or signatures (pass).
    auto pubkey_iterator = pubkeys.begin();
    const chain::script script_code(std::move(ops));
    auto strict = script::is_enabled(context.flags(), rule_fork::bip66_rule);

    for (const auto& endorsement: sigs)
    {
        if (endorsement.empty())
            return signature_parse_result::invalid;

        const auto sighash_type = endorsement.back();
        auto distinguished = endorsement;
        distinguished.pop_back();
        ec_signature signature;

        if (!parse_signature(signature, distinguished, strict))
            return strict ?
                signature_parse_result::lax_encoding :
                signature_parse_result::invalid;

        while (true)
        {
            const auto& point = *pubkey_iterator;

            if (script::check_signature(signature, sighash_type, point,
                script_code, tx, input_index))
                break;

            if (++pubkey_iterator == pubkeys.end())
                return signature_parse_result::invalid;
        }
    }

    return signature_parse_result::valid;
}

static bool op_check_multisig(evaluation_context& context, const script& script,
    const transaction& tx, uint32_t input_index)
{
    switch (op_check_multisig_verify(context, script, tx, input_index))
    {
        case signature_parse_result::valid:
            context.push(true);
            break;
        case signature_parse_result::invalid:
            context.push(false);
            break;
        case signature_parse_result::lax_encoding:
            return false;
    }

    return true;
}

static bool op_check_locktime_verify(evaluation_context& context,
    const script& script, const transaction& tx, uint32_t input_index)
{
    // nop2 is subsumed by checklocktimeverify when bip65 fork is active.
    if (!script::is_enabled(context.flags(), rule_fork::bip65_rule))
        return op_nop(opcode::nop2);

    if (input_index >= tx.inputs().size())
        return false;

    // BIP65: the nSequence field of the txin is 0xffffffff.
    if (tx.inputs()[input_index].is_final())
        return false;

    // BIP65: the stack is empty.
    // BIP65: We extend the (signed) CLTV script number range to 5 bytes in
    // order to reach the domain of the (unsigned) tx.locktime field.
    script_number number;
    if (!context.pop(number, max_cltv_number_size))
        return false;

    // BIP65: the top item on the stack is less than 0.
    if (number < 0)
        return false;

    // TODO: confirm the domain of context.pop_stack() above is uint32_t.
    // If so there is no reason to cast into 64 bit here, just use uint32_t.
    // The value is positive, so it is safe to cast to uint64_t.
    const auto stack = static_cast<uint64_t>(number.int64());

    // BIP65: the stack lock-time type differs from that of tx nLockTime.
    if ((stack < locktime_threshold) != (tx.locktime() < locktime_threshold))
        return false;

    // BIP65: the top stack item is greater than the tx's nLockTime.
    return stack <= tx.locktime();
}

// Validation - run.
//-----------------------------------------------------------------------------

// See BIP16 for max_data_script_size.
// The script paramter is NOT always tx.indexes[input_index].script.
bool interpreter::run(const transaction& tx, uint32_t input_index,
    const script& script, evaluation_context& context)
{
    if (!context.initialize(script))
        return false;

    for (auto op = context.begin(); op != context.end(); ++op)
    {
        if (op->is_oversized() || op->is_disabled())
            return false;

        if (!context.update_op_count(*op))
            return false;

        // Reserved codes may be skipped (allowed) so can't handle prior.
        // Disabled codes can't be skipped so they must be handled prior.
        if (context.is_short_circuited(*op))
            continue;

        if (!run_op(op, tx, input_index, script, context))
            return false;

        if (context.is_stack_overflow())
            return false;
    }

    // Confirm that scopes are paired.
    return context.condition.closed();
}

bool interpreter::run_op(operation::const_iterator op, const transaction& tx,
    uint32_t input_index, const script& script, evaluation_context& context)
{
    const auto code = op->code();
    const auto data = op->data();
    BITCOIN_ASSERT(data.empty() || operation::is_push(code));

    switch (code)
    {
        case opcode::push_size_0:
        case opcode::push_size_1:
        case opcode::push_size_2:
        case opcode::push_size_3:
        case opcode::push_size_4:
        case opcode::push_size_5:
        case opcode::push_size_6:
        case opcode::push_size_7:
        case opcode::push_size_8:
        case opcode::push_size_9:
        case opcode::push_size_10:
        case opcode::push_size_11:
        case opcode::push_size_12:
        case opcode::push_size_13:
        case opcode::push_size_14:
        case opcode::push_size_15:
        case opcode::push_size_16:
        case opcode::push_size_17:
        case opcode::push_size_18:
        case opcode::push_size_19:
        case opcode::push_size_20:
        case opcode::push_size_21:
        case opcode::push_size_22:
        case opcode::push_size_23:
        case opcode::push_size_24:
        case opcode::push_size_25:
        case opcode::push_size_26:
        case opcode::push_size_27:
        case opcode::push_size_28:
        case opcode::push_size_29:
        case opcode::push_size_30:
        case opcode::push_size_31:
        case opcode::push_size_32:
        case opcode::push_size_33:
        case opcode::push_size_34:
        case opcode::push_size_35:
        case opcode::push_size_36:
        case opcode::push_size_37:
        case opcode::push_size_38:
        case opcode::push_size_39:
        case opcode::push_size_40:
        case opcode::push_size_41:
        case opcode::push_size_42:
        case opcode::push_size_43:
        case opcode::push_size_44:
        case opcode::push_size_45:
        case opcode::push_size_46:
        case opcode::push_size_47:
        case opcode::push_size_48:
        case opcode::push_size_49:
        case opcode::push_size_50:
        case opcode::push_size_51:
        case opcode::push_size_52:
        case opcode::push_size_53:
        case opcode::push_size_54:
        case opcode::push_size_55:
        case opcode::push_size_56:
        case opcode::push_size_57:
        case opcode::push_size_58:
        case opcode::push_size_59:
        case opcode::push_size_60:
        case opcode::push_size_61:
        case opcode::push_size_62:
        case opcode::push_size_63:
        case opcode::push_size_64:
        case opcode::push_size_65:
        case opcode::push_size_66:
        case opcode::push_size_67:
        case opcode::push_size_68:
        case opcode::push_size_69:
        case opcode::push_size_70:
        case opcode::push_size_71:
        case opcode::push_size_72:
        case opcode::push_size_73:
        case opcode::push_size_74:
        case opcode::push_size_75:
            return op_push_size(context, *op);
        case opcode::push_one_size:
            return op_push_size(context, data, max_uint8);
        case opcode::push_two_size:
            return op_push_size(context, data, max_uint16);
        case opcode::push_four_size:
            return op_push_size(context, data, max_uint32);
        case opcode::push_negative_1:
            return op_push_number(context, script_number::negative_1);
        case opcode::reserved_80:
            return op_reserved(code);
        case opcode::push_positive_1:
            return op_push_number(context, script_number::positive_1);
        case opcode::push_positive_2:
            return op_push_number(context, script_number::positive_2);
        case opcode::push_positive_3:
            return op_push_number(context, script_number::positive_3);
        case opcode::push_positive_4:
            return op_push_number(context, script_number::positive_4);
        case opcode::push_positive_5:
            return op_push_number(context, script_number::positive_5);
        case opcode::push_positive_6:
            return op_push_number(context, script_number::positive_6);
        case opcode::push_positive_7:
            return op_push_number(context, script_number::positive_7);
        case opcode::push_positive_8:
            return op_push_number(context, script_number::positive_8);
        case opcode::push_positive_9:
            return op_push_number(context, script_number::positive_9);
        case opcode::push_positive_10:
            return op_push_number(context, script_number::positive_10);
        case opcode::push_positive_11:
            return op_push_number(context, script_number::positive_11);
        case opcode::push_positive_12:
            return op_push_number(context, script_number::positive_12);
        case opcode::push_positive_13:
            return op_push_number(context, script_number::positive_13);
        case opcode::push_positive_14:
            return op_push_number(context, script_number::positive_14);
        case opcode::push_positive_15:
            return op_push_number(context, script_number::positive_15);
        case opcode::push_positive_16:
            return op_push_number(context, script_number::positive_16);
        case opcode::nop:
            return op_nop(code);
        case opcode::reserved_98:
            return op_reserved(code);
        case opcode::if_:
            return op_if(context);
        case opcode::notif:
            return op_notif(context);
        case opcode::reserved_101:
            return op_reserved(code);
        case opcode::reserved_102:
            return op_reserved(code);
        case opcode::else_:
            return op_else(context);
        case opcode::endif:
            return op_endif(context);
        case opcode::verify:
            return op_verify(context);
        case opcode::return_:
            return op_return(context);
        case opcode::toaltstack:
            return op_to_alt_stack(context);
        case opcode::fromaltstack:
            return op_from_alt_stack(context);
        case opcode::drop2:
            return op_drop2(context);
        case opcode::dup2:
            return op_dup2(context);
        case opcode::dup3:
            return op_dup3(context);
        case opcode::over2:
            return op_over2(context);
        case opcode::rot2:
            return op_rot2(context);
        case opcode::swap2:
            return op_swap2(context);
        case opcode::ifdup:
            return op_if_dup(context);
        case opcode::depth:
            return op_depth(context);
        case opcode::drop:
            return op_drop(context);
        case opcode::dup:
            return op_dup(context);
        case opcode::nip:
            return op_nip(context);
        case opcode::over:
            return op_over(context);
        case opcode::pick:
            return op_pick(context);
        case opcode::roll:
            return op_roll(context);
        case opcode::rot:
            return op_rot(context);
        case opcode::swap:
            return op_swap(context);
        case opcode::tuck:
            return op_tuck(context);
        case opcode::disabled_cat:
            return op_disabled(code);
        case opcode::disabled_substr:
            return op_disabled(code);
        case opcode::disabled_left:
            return op_disabled(code);
        case opcode::disabled_right:
            return op_disabled(code);
        case opcode::size:
            return op_size(context);
        case opcode::disabled_invert:
            return op_disabled(code);
        case opcode::disabled_and:
            return op_disabled(code);
        case opcode::disabled_or:
            return op_disabled(code);
        case opcode::disabled_xor:
            return op_disabled(code);
        case opcode::equal:
            return op_equal(context);
        case opcode::equalverify:
            return op_equal_verify(context);
        case opcode::reserved_137:
            return op_reserved(code);
        case opcode::reserved_138:
            return op_reserved(code);
        case opcode::add1:
            return op_add1(context);
        case opcode::sub1:
            return op_sub1(context);
        case opcode::disabled_mul2:
            return op_disabled(code);
        case opcode::disabled_div2:
            return op_disabled(code);
        case opcode::negate:
            return op_negate(context);
        case opcode::abs:
            return op_abs(context);
        case opcode::not:
            return op_not(context);
        case opcode::nonzero:
            return op_nonzero(context);
        case opcode::add:
            return op_add(context);
        case opcode::sub:
            return op_sub(context);
        case opcode::disabled_mul:
            return op_disabled(code);
        case opcode::disabled_div:
            return op_disabled(code);
        case opcode::disabled_mod:
            return op_disabled(code);
        case opcode::disabled_lshift:
            return op_disabled(code);
        case opcode::disabled_rshift:
            return op_disabled(code);
        case opcode::booland:
            return op_bool_and(context);
        case opcode::boolor:
            return op_bool_or(context);
        case opcode::numequal:
            return op_num_equal(context);
        case opcode::numequalverify:
            return op_num_equal_verify(context);
        case opcode::numnotequal:
            return op_num_not_equal(context);
        case opcode::lessthan:
            return op_less_than(context);
        case opcode::greaterthan:
            return op_greater_than(context);
        case opcode::lessthanorequal:
            return op_less_than_or_equal(context);
        case opcode::greaterthanorequal:
            return op_greater_than_or_equal(context);
        case opcode::min:
            return op_min(context);
        case opcode::max:
            return op_max(context);
        case opcode::within:
            return op_within(context);
        case opcode::ripemd160:
            return op_ripemd160(context);
        case opcode::sha1:
            return op_sha1(context);
        case opcode::sha256:
            return op_sha256(context);
        case opcode::hash160:
            return op_hash160(context);
        case opcode::hash256:
            return op_hash256(context);
        case opcode::codeseparator:
            return op_code_seperator(context, op);
        case opcode::checksig:
            return op_check_sig(context, script, tx, input_index);
        case opcode::checksigverify:
            return op_check_sig_verify(context, script, tx, input_index) ==
                signature_parse_result::valid;
        case opcode::checkmultisig:
            return op_check_multisig(context, script, tx, input_index);
        case opcode::checkmultisigverify:
            return op_check_multisig_verify(context, script, tx, input_index) ==
                signature_parse_result::valid;
        case opcode::nop1:
            return op_nop(code);
        case opcode::checklocktimeverify:
            return op_check_locktime_verify(context, script, tx, input_index);
        case opcode::nop3:
        case opcode::nop4:
        case opcode::nop5:
        case opcode::nop6:
        case opcode::nop7:
        case opcode::nop8:
        case opcode::nop9:
        case opcode::nop10:
            return op_nop(code);
        case opcode::reserved_186:
        case opcode::reserved_187:
        case opcode::reserved_188:
        case opcode::reserved_189:
        case opcode::reserved_190:
        case opcode::reserved_191:
        case opcode::reserved_192:
        case opcode::reserved_193:
        case opcode::reserved_194:
        case opcode::reserved_195:
        case opcode::reserved_196:
        case opcode::reserved_197:
        case opcode::reserved_198:
        case opcode::reserved_199:
        case opcode::reserved_200:
        case opcode::reserved_201:
        case opcode::reserved_202:
        case opcode::reserved_203:
        case opcode::reserved_204:
        case opcode::reserved_205:
        case opcode::reserved_206:
        case opcode::reserved_207:
        case opcode::reserved_208:
        case opcode::reserved_209:
        case opcode::reserved_210:
        case opcode::reserved_211:
        case opcode::reserved_212:
        case opcode::reserved_213:
        case opcode::reserved_214:
        case opcode::reserved_215:
        case opcode::reserved_216:
        case opcode::reserved_217:
        case opcode::reserved_218:
        case opcode::reserved_219:
        case opcode::reserved_220:
        case opcode::reserved_221:
        case opcode::reserved_222:
        case opcode::reserved_223:
        case opcode::reserved_224:
        case opcode::reserved_225:
        case opcode::reserved_226:
        case opcode::reserved_227:
        case opcode::reserved_228:
        case opcode::reserved_229:
        case opcode::reserved_230:
        case opcode::reserved_231:
        case opcode::reserved_232:
        case opcode::reserved_233:
        case opcode::reserved_234:
        case opcode::reserved_235:
        case opcode::reserved_236:
        case opcode::reserved_237:
        case opcode::reserved_238:
        case opcode::reserved_239:
        case opcode::reserved_240:
        case opcode::reserved_241:
        case opcode::reserved_242:
        case opcode::reserved_243:
        case opcode::reserved_244:
        case opcode::reserved_245:
        case opcode::reserved_246:
        case opcode::reserved_247:
        case opcode::reserved_248:
        case opcode::reserved_249:
        case opcode::reserved_250:
        case opcode::reserved_251:
        case opcode::reserved_252:
        case opcode::reserved_253:
        case opcode::reserved_254:
        case opcode::reserved_255:
        default:
            return op_reserved(code);
    }
}

} // namespace chain
} // namespace libbitcoin
