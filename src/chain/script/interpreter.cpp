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

static bool op_zero(evaluation_context& context)
{
    context.stack.emplace_back();
    return true;
}

// TODO: look into moving op.data() here.
static bool op_special(evaluation_context& context, const data_chunk& data)
{
    BITCOIN_ASSERT(data.size() > static_cast<uint8_t>(opcode::zero));
    BITCOIN_ASSERT(data.size() < static_cast<uint8_t>(opcode::pushdata1));
    context.stack.push_back(data);
    return true;
}

// TODO: look into moving op.data() here.
static bool op_pushdata1(evaluation_context& context, const data_chunk& data)
{
    BITCOIN_ASSERT(data.size() >= static_cast<uint8_t>(opcode::pushdata1));
    BITCOIN_ASSERT(data.size() <= max_uint8);
    context.stack.push_back(data);
    return true;
}

// TODO: look into moving op.data() here.
static bool op_pushdata2(evaluation_context& context, const data_chunk& data)
{
    BITCOIN_ASSERT(data.size() > max_uint8);
    BITCOIN_ASSERT(data.size() <= max_uint16);
    context.stack.push_back(data);
    return true;
}

// TODO: look into moving op.data() here.
static bool op_pushdata4(evaluation_context& context, const data_chunk& data)
{
    BITCOIN_ASSERT(data.size() > max_uint16);
    BITCOIN_ASSERT(data.size() <= max_uint32);
    context.stack.push_back(data);
    return true;
}

static bool op_negative_1(evaluation_context& context)
{
    context.stack.emplace_back(script_number::negative_1);
    return true;
}

static bool op_positive_1(evaluation_context& context)
{
    context.stack.emplace_back(script_number::positive_1);
    return true;
}

static bool op_positive_2(evaluation_context& context)
{
    context.stack.emplace_back(script_number::positive_2);
    return true;
}

static bool op_positive_3(evaluation_context& context)
{
    context.stack.emplace_back(script_number::positive_3);
    return true;
}

static bool op_positive_4(evaluation_context& context)
{
    context.stack.emplace_back(script_number::positive_4);
    return true;
}

static bool op_positive_5(evaluation_context& context)
{
    context.stack.emplace_back(script_number::positive_5);
    return true;
}

static bool op_positive_6(evaluation_context& context)
{
    context.stack.emplace_back(script_number::positive_6);
    return true;
}

static bool op_positive_7(evaluation_context& context)
{
    context.stack.emplace_back(script_number::positive_7);
    return true;
}

static bool op_positive_8(evaluation_context& context)
{
    context.stack.emplace_back(script_number::positive_8);
    return true;
}

static bool op_positive_9(evaluation_context& context)
{
    context.stack.emplace_back(script_number::positive_9);
    return true;
}

static bool op_positive_10(evaluation_context& context)
{
    context.stack.emplace_back(script_number::positive_10);
    return true;
}

static bool op_positive_11(evaluation_context& context)
{
    context.stack.emplace_back(script_number::positive_11);
    return true;
}

static bool op_positive_12(evaluation_context& context)
{
    context.stack.emplace_back(script_number::positive_12);
    return true;
}

static bool op_positive_13(evaluation_context& context)
{
    context.stack.emplace_back(script_number::positive_13);
    return true;
}

static bool op_positive_14(evaluation_context& context)
{
    context.stack.emplace_back(script_number::positive_14);
    return true;
}

static bool op_positive_15(evaluation_context& context)
{
    context.stack.emplace_back(script_number::positive_15);
    return true;
}

static bool op_positive_16(evaluation_context& context)
{
    context.stack.emplace_back(script_number::positive_16);
    return true;
}

static bool op_nop(evaluation_context& context)
{
    return true;
}

static bool op_if(evaluation_context& context)
{
    auto value = false;

    if (context.condition.succeeded())
    {
        if (context.stack.empty())
            return false;

        value = context.stack_result();
        context.pop();
    }

    context.condition.open(value);
    return true;
}

static bool op_notif(evaluation_context& context)
{
    if (!op_if(context))
        return false;

    // Open IF and invert for NOTIF.
    context.condition.negate();
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

    if (!context.stack_result())
        return false;

    context.pop();
    return true;
}

static bool op_return(evaluation_context& context)
{
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

    context.stack.push_back(context.item(1));
    context.stack.push_back(context.item(0));
    return true;
}

static bool op_dup3(evaluation_context& context)
{
    if (context.stack.size() < 3)
        return false;

    context.stack.push_back(context.item(2));
    context.stack.push_back(context.item(1));
    context.stack.push_back(context.item(0));
    return true;
}

static bool op_over2(evaluation_context& context)
{
    if (context.stack.size() < 4)
        return false;

    // Size changes after first duplicate.
    context.duplicate(3);
    context.duplicate(3);
    return true;
}

static bool op_rot2(evaluation_context& context)
{
    if (context.stack.size() < 6)
        return false;

    const auto position_1 = context.position(5);
    const auto position_2 = context.position(4);

    const auto copy_1 = *position_1;
    const auto copy_2 = *position_2;

    context.stack.erase(position_1, position_2 + 1);
    context.stack.emplace_back(std::move(copy_1));
    context.stack.emplace_back(std::move(copy_2));
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

    if (context.stack_result())
        context.stack.push_back(context.stack.back());

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

    context.stack.pop_back();
    return true;
}

static bool op_dup(evaluation_context& context)
{
    if (context.stack.empty())
        return false;

    context.stack.push_back(context.stack.back());
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
    const auto result = first - second;
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

    context.push(first < second);
    return true;
}

static bool op_greater_than(evaluation_context& context)
{
    script_number first, second;
    if (!context.pop_binary(first, second))
        return false;

    context.push(first > second);
    return true;
}

static bool op_less_than_or_equal(evaluation_context& context)
{
    script_number first, second;
    if (!context.pop_binary(first, second))
        return false;

    context.push(first <= second);
    return true;
}

static bool op_greater_than_or_equal(evaluation_context& context)
{
    script_number first, second;
    if (!context.pop_binary(first, second))
        return false;

    context.push(first >= second);
    return true;
}

static bool op_min(evaluation_context& context)
{
    script_number first, second;
    if (!context.pop_binary(first, second))
        return false;

    if (first < second)
        context.stack.push_back(first.data());
    else
        context.stack.push_back(second.data());

    return true;
}

static bool op_max(evaluation_context& context)
{
    script_number first, second;
    if (!context.pop_binary(first, second))
        return false;

    auto greater = first > second ? first.data() : second.data();
    context.stack.emplace_back(std::move(greater));
    return true;
}

static bool op_within(evaluation_context& context)
{
    script_number upper, lower, value;
    if (!context.pop_ternary(upper, lower, value))
        return false;

    context.push(lower <= value && value < upper);
    return true;
}

static bool op_ripemd160(evaluation_context& context)
{
    if (context.stack.empty())
        return false;

    const auto hash = ripemd160_hash(context.pop());
    context.stack.push_back(to_chunk(hash));
    return true;
}

static bool op_sha1(evaluation_context& context)
{
    if (context.stack.empty())
        return false;

    const auto hash = sha1_hash(context.pop());
    context.stack.push_back(to_chunk(hash));
    return true;
}

static bool op_sha256(evaluation_context& context)
{
    if (context.stack.empty())
        return false;

    const auto hash = sha256_hash(context.pop());
    context.stack.push_back(to_chunk(hash));
    return true;
}

static bool op_hash160(evaluation_context& context)
{
    if (context.stack.empty())
        return false;

    const auto hash = bitcoin_short_hash(context.pop());
    context.stack.push_back(to_chunk(hash));
    return true;
}

static bool op_hash256(evaluation_context& context)
{
    if (context.stack.empty())
        return false;

    const auto hash = bitcoin_hash(context.pop());
    context.stack.push_back(to_chunk(hash));
    return true;
}

static bool op_code_seperator(evaluation_context& context,
    operation::stack::const_iterator op)
{
    // Modify context.begin() for the next op_check_[multi_]sig_verify call.
    context.reset(op);
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

    if (strict && !parse_signature(signature, distinguished, true))
        return signature_parse_result::lax_encoding;

    chain::script script_code;

    for (auto op = context.begin(); op != context.end(); ++op)
        if (op->code() != opcode::codeseparator && op->data() != endorsement)
            script_code.operations().push_back(*op);

    if (!strict && !parse_signature(signature, distinguished, false))
        return signature_parse_result::invalid;

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

    data_stack endorsements;
    if (!context.pop(endorsements, sigs_count))
        return signature_parse_result::invalid;

    // Due to a bug in bitcoind, we need to read an extra null value which we
    // discard later.
    if (context.stack.empty())
        return signature_parse_result::invalid;

    context.stack.pop_back();
    const auto is_endorsement = [&endorsements](const data_chunk& data)
    {
        return std::find(endorsements.begin(), endorsements.end(), data) !=
            endorsements.end();
    };

    chain::script script_code;

    for (auto op = context.begin(); op != context.end(); ++op)
        if (op->code() != opcode::codeseparator && !is_endorsement(op->data()))
            script_code.operations().push_back(*op);

    // The exact number of signatures are required and must be in order.
    // One key can validate more than one script. So we always advance 
    // until we exhaust either pubkeys (fail) or signatures (pass).
    auto pubkey_iterator = pubkeys.begin();
    auto strict = script::is_enabled(context.flags(), rule_fork::bip66_rule);

    for (const auto& endorsement: endorsements)
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

            ++pubkey_iterator;

            if (pubkey_iterator == pubkeys.end())
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
        return op_nop(context);

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

    // If any op returns false the execution terminates and is false.
    for (auto op = context.begin(); op != context.end(); ++op)
    {
        // failure: static
        if (op->data().size() > max_data_script_size ||
            !operation::is_operational(op->code()) ||
            !context.update_op_count(op->code()))
            return false;

        // short circut this operation
        if (!operation::is_conditional(op->code()) &&
            !context.condition.succeeded())
            continue;

        // failure: dynamic
        if (!run_op(op, tx, input_index, script, context) ||
            context.is_stack_overflow())
            return false;
    }

    // Confirm that scopes are paired.
    return context.condition.closed();
}

bool interpreter::run_op(operation::stack::const_iterator op,
    const transaction& tx, uint32_t input_index, const script& script,
    evaluation_context& context)
{
    BITCOIN_ASSERT(op->data().empty() ||
        op->code() == opcode::special ||
        op->code() == opcode::pushdata1 ||
        op->code() == opcode::pushdata2 ||
        op->code() == opcode::pushdata4);

    switch (op->code())
    {
        case opcode::zero:
            return op_zero(context);
        case opcode::special:
            return op_special(context, op->data());
        case opcode::pushdata1:
            return op_pushdata1(context, op->data());
        case opcode::pushdata2:
            return op_pushdata2(context, op->data());
        case opcode::pushdata4:
            return op_pushdata4(context, op->data());
        case opcode::negative_1:
            return op_negative_1(context);
        case opcode::positive_1:
            return op_positive_1(context);
        case opcode::positive_2:
            return op_positive_2(context);
        case opcode::positive_3:
            return op_positive_3(context);
        case opcode::positive_4:
            return op_positive_4(context);
        case opcode::positive_5:
            return op_positive_5(context);
        case opcode::positive_6:
            return op_positive_6(context);
        case opcode::positive_7:
            return op_positive_7(context);
        case opcode::positive_8:
            return op_positive_8(context);
        case opcode::positive_9:
            return op_positive_9(context);
        case opcode::positive_10:
            return op_positive_10(context);
        case opcode::positive_11:
            return op_positive_11(context);
        case opcode::positive_12:
            return op_positive_12(context);
        case opcode::positive_13:
            return op_positive_13(context);
        case opcode::positive_14:
            return op_positive_14(context);
        case opcode::positive_15:
            return op_positive_15(context);
        case opcode::positive_16:
            return op_positive_16(context);
        case opcode::if_:
            return op_if(context);
        case opcode::notif:
            return op_notif(context);
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
        case opcode::size:
            return op_size(context);
        case opcode::equal:
            return op_equal(context);
        case opcode::equalverify:
            return op_equal_verify(context);
        case opcode::add1:
            return op_add1(context);
        case opcode::sub1:
            return op_sub1(context);
        case opcode::negate:
            return op_negate(context);
        case opcode::abs:
            return op_abs(context);
        case opcode::not_:
            return op_not(context);
        case opcode::nonzero:
            return op_nonzero(context);
        case opcode::add:
            return op_add(context);
        case opcode::sub:
            return op_sub(context);
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
            return op_check_sig_verify(context, script, tx, input_index) == signature_parse_result::valid;
        case opcode::checkmultisig:
            return op_check_multisig(context, script, tx, input_index);
        case opcode::checkmultisigverify:
            return op_check_multisig_verify(context, script, tx, input_index) == signature_parse_result::valid;
        case opcode::checklocktimeverify:
             return op_check_locktime_verify(context, script, tx, input_index);
        case opcode::nop:
            return op_nop(context);
        case opcode::nop1:
            return op_nop(context);
        ////case opcode::nop2:
        ////    return op_nop(context);
        case opcode::nop3:
            return op_nop(context);
        case opcode::nop4:
            return op_nop(context);
        case opcode::nop5:
            return op_nop(context);
        case opcode::nop6:
            return op_nop(context);
        case opcode::nop7:
            return op_nop(context);
        case opcode::nop8:
            return op_nop(context);
        case opcode::nop9:
            return op_nop(context);
        case opcode::nop10:
            return op_nop(context);
        default:
            BITCOIN_ASSERT_MSG(false, "Cannot run non-operational op code.");
            return false;
    }
}

} // namespace chain
} // namespace libbitcoin
