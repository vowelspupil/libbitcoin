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

inline void report(const char*)
{
    // Don't assert here since invalid script values are possible due to public
    // access to the script stack. Our test cases populate these values even in
    // the cases where the script parser may not.
    ////BITCOIN_ASSERT_MSG(false, message);
}

inline data_chunk bool_to_stack(bool value)
{
    return value ? data_chunk{ 1 } : data_chunk{};
}

// Stack manipulation.
//-----------------------------------------------------------------------------

inline data_stack::iterator position(evaluation_context& context,
    size_t back_index)
{
    return context.stack.end() - back_index;
}

inline data_chunk& item(evaluation_context& context, size_t back_index)
{
    return *position(context, back_index);
}

inline void swap_items(evaluation_context& context, size_t back_index_left,
    size_t back_index_right)
{
    std::swap(item(context, back_index_left), item(context, back_index_right));
}

inline void duplicate_item(evaluation_context& context, size_t back_index)
{
    context.stack.push_back(item(context, back_index));
}

inline bool pop_unary(evaluation_context& context, script_number& out_number,
    size_t maxiumum_size=max_number_size)
{
    return !context.stack.empty() &&
        out_number.set_data(context.pop_stack(), maxiumum_size);
}

inline bool pop_unary(evaluation_context& context, int32_t& out_value)
{
    script_number middle;
    if (!pop_unary(context, middle))
        return false;

    out_value = middle.int32();
    return true;
}

inline bool pop_binary(evaluation_context& context,
    script_number& left, script_number& right)
{
    // The right hand side number is at the top of the stack.
    return pop_unary(context, right) && pop_unary(context, left);
}

inline bool pop_ternary(evaluation_context& context,
    script_number& upper, script_number& lower, script_number& value)
{
    // The upper bound is at the top of the stack and the lower bound next.
    return pop_unary(context, upper) && pop_unary(context, lower) &&
        pop_unary(context, value);
}

// Determines if the value is a valid stack index and returns the index.
inline bool pop_position(evaluation_context& context,
    data_stack::iterator& out_position)
{
    int32_t index;
    if (!pop_unary(context, index))
        return false;

    // Ensure the index is within bounds.
    const auto size = context.stack.size();
    if (index < 0 || index >= size)
        return false;

    // index is zero-based and position is one-based.
    const auto back_index = index + 1;

    out_position = position(context, back_index);
    return true;
}

static bool read_section(evaluation_context& context, data_stack& section,
    size_t count)
{
    if (context.stack.size() < count)
        return false;

    for (size_t i = 0; i < count; ++i)
        section.push_back(context.pop_stack());

    return true;
}

// Operations.
//-----------------------------------------------------------------------------

static bool op_negative_1(evaluation_context& context)
{
    context.stack.emplace_back(script_number::negative_1);
    return true;
}

static bool op_n(evaluation_context& context, opcode code)
{
    static const auto code_0 = static_cast<uint8_t>(opcode::op_1) - 1;
    const auto span = static_cast<uint8_t>(code)-code_0;
    context.stack.push_back(script_number(span).data());
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

        value = context.stack_to_bool();
        context.pop_stack();
    }

    context.condition.open(value);
    return true;
}

static bool op_notif(evaluation_context& context)
{
    // A bit hackish...
    // Open IF statement but then invert it to get NOTIF
    if (!op_if(context))
        return false;

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

    if (!context.stack_to_bool())
        return false;

    context.pop_stack();
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

    context.alternate.push_back(context.pop_stack());
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

    context.stack.push_back(item(context, 2));
    context.stack.push_back(item(context, 1));
    return true;
}

static bool op_dup3(evaluation_context& context)
{
    if (context.stack.size() < 3)
        return false;

    context.stack.push_back(item(context, 3));
    context.stack.push_back(item(context, 2));
    context.stack.push_back(item(context, 1));
    return true;
}

// (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
static bool op_over2(evaluation_context& context)
{
    if (context.stack.size() < 4)
        return false;

    // Item -3 becomes -4 because of first copy.
    duplicate_item(context, 4);
    duplicate_item(context, 4);
    return true;
}

// (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
static bool op_rot2(evaluation_context& context)
{
    if (context.stack.size() < 6)
        return false;

    const auto position_1 = position(context, 6);
    const auto position_2 = position(context, 5);

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

    swap_items(context, 4, 2);
    swap_items(context, 3, 1);
    return true;
}

static bool op_if_dup(evaluation_context& context)
{
    if (context.stack.empty())
        return false;

    if (context.stack_to_bool())
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

    context.stack.erase(position(context, 2));
    return true;
}

static bool op_over(evaluation_context& context)
{
    if (context.stack.size() < 2)
        return false;

    duplicate_item(context, 2);
    return true;
}

static bool op_pick(evaluation_context& context)
{
    data_stack::iterator position;
    if (!pop_position(context, position))
        return false;

    context.stack.push_back(*position);
    return true;
}

static bool op_roll(evaluation_context& context)
{
    data_stack::iterator position;
    if (!pop_position(context, position))
        return false;

    auto copy = *position;
    context.stack.erase(position);
    context.stack.emplace_back(std::move(copy));
    return true;
}

static bool op_rot(evaluation_context& context)
{
    // Top 3 stack items are rotated to the left.
    // Before: x1 x2 x3
    // After:  x2 x3 x1
    if (context.stack.size() < 3)
        return false;

    swap_items(context, 3, 2);
    swap_items(context, 2, 1);
    return true;
}

static bool op_swap(evaluation_context& context)
{
    if (context.stack.size() < 2)
        return false;

    swap_items(context, 2, 1);
    return true;
}

static bool op_tuck(evaluation_context& context)
{
    if (context.stack.size() < 2)
        return false;

    context.stack.insert(position(context, 2), context.stack.back());
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

    const auto value = context.pop_stack() == context.pop_stack();
    context.stack.push_back(bool_to_stack(value));
    return true;
}

static bool op_equal_verify(evaluation_context& context)
{
    if (context.stack.size() < 2)
        return false;

    return context.pop_stack() == context.pop_stack();
}

static bool op_add1(evaluation_context& context)
{
    script_number number;
    if (!pop_unary(context, number))
        return false;

    number += 1;
    context.stack.push_back(number.data());
    return true;
}

static bool op_sub1(evaluation_context& context)
{
    script_number number;
    if (!pop_unary(context, number))
        return false;

    number -= 1;
    context.stack.push_back(number.data());
    return true;
}

static bool op_negate(evaluation_context& context)
{
    script_number number;
    if (!pop_unary(context, number))
        return false;

    number = -number;
    context.stack.push_back(number.data());
    return true;
}

static bool op_abs(evaluation_context& context)
{
    script_number number;
    if (!pop_unary(context, number))
        return false;

    if (number < 0)
        number = -number;

    context.stack.push_back(number.data());
    return true;
}

static bool op_not(evaluation_context& context)
{
    script_number number;
    if (!pop_unary(context, number))
        return false;

    context.stack.push_back(bool_to_stack(number == 0));
    return true;
}

static bool op_nonzero(evaluation_context& context)
{
    script_number number;
    if (!pop_unary(context, number))
        return false;

    context.stack.push_back(bool_to_stack(number != 0));
    return true;
}

static bool op_add(evaluation_context& context)
{
    script_number left, right;
    if (!pop_binary(context, left, right))
        return false;

    const auto result = left + right;
    context.stack.push_back(result.data());
    return true;
}

static bool op_sub(evaluation_context& context)
{
    script_number left, right;
    if (!pop_binary(context, left, right))
        return false;

    const auto result = left - right;
    context.stack.push_back(result.data());
    return true;
}

static bool op_bool_and(evaluation_context& context)
{
    script_number left, right;
    if (!pop_binary(context, left, right))
        return false;

    context.stack.push_back(bool_to_stack(left != 0 && right != 0));
    return true;
}

static bool op_bool_or(evaluation_context& context)
{
    script_number left, right;
    if (!pop_binary(context, left, right))
        return false;

    context.stack.push_back(bool_to_stack(left != 0 || right != 0));
    return true;
}

static bool op_num_equal(evaluation_context& context)
{
    script_number left, right;
    if (!pop_binary(context, left, right))
        return false;

    context.stack.push_back(bool_to_stack(left == right));
    return true;
}

static bool op_num_equal_verify(evaluation_context& context)
{
    script_number left, right;
    if (!pop_binary(context, left, right))
        return false;

    return left == right;
}

static bool op_num_not_equal(evaluation_context& context)
{
    script_number left, right;
    if (!pop_binary(context, left, right))
        return false;

    context.stack.push_back(bool_to_stack(left != right));
    return true;
}

static bool op_less_than(evaluation_context& context)
{
    script_number left, right;
    if (!pop_binary(context, left, right))
        return false;

    context.stack.push_back(bool_to_stack(left < right));
    return true;
}

static bool op_greater_than(evaluation_context& context)
{
    script_number left, right;
    if (!pop_binary(context, left, right))
        return false;

    context.stack.push_back(bool_to_stack(left > right));
    return true;
}

static bool op_less_than_or_equal(evaluation_context& context)
{
    script_number left, right;
    if (!pop_binary(context, left, right))
        return false;

    context.stack.push_back(bool_to_stack(left <= right));
    return true;
}

static bool op_greater_than_or_equal(evaluation_context& context)
{
    script_number left, right;
    if (!pop_binary(context, left, right))
        return false;

    context.stack.push_back(bool_to_stack(left >= right));
    return true;
}

static bool op_min(evaluation_context& context)
{
    script_number left, right;
    if (!pop_binary(context, left, right))
        return false;

    if (left < right)
        context.stack.push_back(left.data());
    else
        context.stack.push_back(right.data());

    return true;
}

static bool op_max(evaluation_context& context)
{
    script_number left, right;
    if (!pop_binary(context, left, right))
        return false;

    auto greater = left > right ? left.data() : right.data();
    context.stack.emplace_back(std::move(greater));
    return true;
}

static bool op_within(evaluation_context& context)
{
    script_number upper, lower, value;
    if (!pop_ternary(context, upper, lower, value))
        return false;

    context.stack.push_back(bool_to_stack(lower <= value && value < upper));
    return true;
}

static bool op_ripemd160(evaluation_context& context)
{
    if (context.stack.empty())
        return false;

    const auto hash = ripemd160_hash(context.pop_stack());
    context.stack.push_back(to_chunk(hash));
    return true;
}

static bool op_sha1(evaluation_context& context)
{
    if (context.stack.empty())
        return false;

    const auto hash = sha1_hash(context.pop_stack());
    context.stack.push_back(to_chunk(hash));
    return true;
}

static bool op_sha256(evaluation_context& context)
{
    if (context.stack.empty())
        return false;

    const auto hash = sha256_hash(context.pop_stack());
    context.stack.push_back(to_chunk(hash));
    return true;
}

static bool op_hash160(evaluation_context& context)
{
    if (context.stack.empty())
        return false;

    const auto hash = bitcoin_short_hash(context.pop_stack());
    context.stack.push_back(to_chunk(hash));
    return true;
}

static bool op_hash256(evaluation_context& context)
{
    if (context.stack.empty())
        return false;

    const auto hash = bitcoin_hash(context.pop_stack());
    context.stack.push_back(to_chunk(hash));
    return true;
}

static signature_parse_result op_check_sig_verify(evaluation_context& context,
    const script& script, const transaction& tx, uint32_t input_index)
{
    if (context.stack.size() < 2)
        return signature_parse_result::invalid;

    const auto pubkey = context.pop_stack();
    auto endorsement = context.pop_stack();

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
            context.stack.push_back(bool_to_stack(true));
            break;
        case signature_parse_result::invalid:
            context.stack.push_back(bool_to_stack(false));
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
    if (!pop_unary(context, pubkeys_count))
        return signature_parse_result::invalid;

    if (!context.update_pubkey_count(pubkeys_count))
        return signature_parse_result::invalid;

    data_stack pubkeys;
    if (!read_section(context, pubkeys, pubkeys_count))
        return signature_parse_result::invalid;

    int32_t sigs_count;
    if (!pop_unary(context, sigs_count))
        return signature_parse_result::invalid;

    if (sigs_count < 0 || sigs_count > pubkeys_count)
        return signature_parse_result::invalid;

    data_stack endorsements;
    if (!read_section(context, endorsements, sigs_count))
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
            context.stack.push_back(bool_to_stack(true));
            break;
        case signature_parse_result::invalid:
            context.stack.push_back(bool_to_stack(false));
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
    if (!pop_unary(context, number, max_cltv_number_size))
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

// The script paramter is NOT always tx.indexes[input_index].script.
bool interpreter::run(const transaction& tx, uint32_t input_index,
    const script& script, evaluation_context& context)
{
    if (!context.evaluate(script))
        return false;

    // If any op returns false the execution terminates and is false.
    for (auto op = context.begin(); op != context.end(); ++op)
        if (!next_op(tx, input_index, op, script, context))
            return false;

    // Confirm that scopes are paired.
    return context.condition.closed();
}

bool interpreter::next_op(const transaction& tx, uint32_t input_index,
    operation::stack::const_iterator op, const script& script,
    evaluation_context& context)
{
    // See BIP16
    if (op->data().size() > max_data_script_size)
        return false;

    const auto code = op->code();

    if (!operation::is_operational(code) || !context.update_op_count(code))
        return false;

    if (!operation::is_conditional(code) && !context.condition.succeeded())
        return true;

    return run_op(op, tx, input_index, script, context) &&
        !context.is_stack_overflow();
}

bool interpreter::run_op(operation::stack::const_iterator op, const transaction& tx,
    uint32_t input_index, const script& script, evaluation_context& context)
{
    switch (op->code())
    {
        // Push (data) codes.
        //---------------------------------------------------------------------

        case opcode::zero:
            ////BITCOIN_ASSERT(op->data().empty());
            return true;

        case opcode::special:
            ////BITCOIN_ASSERT(op->data().size() == static_cast<uint8_t>(op.code()));
            context.stack.push_back(op->data());
            return true;

        case opcode::pushdata1:
            ////BITCOIN_ASSERT(op->data().size() < max_uint8);
            ////BITCOIN_ASSERT(op->data().size() > static_cast<uint8_t>(opcode::prefix75));
            context.stack.push_back(op->data());
            return true;

        case opcode::pushdata2:
            ////BITCOIN_ASSERT(op->data().size() < max_uint16);
            ////BITCOIN_ASSERT(op->data().size() > static_cast<uint8_t>(opcode::prefix75));
            context.stack.push_back(op->data());
            return true;

        case opcode::pushdata4:
            ////BITCOIN_ASSERT(op->data().size() < max_uint32);
            ////BITCOIN_ASSERT(op->data().size() > static_cast<uint8_t>(opcode::prefix75));
            context.stack.push_back(op->data());
            return true;

        case opcode::negative_1:
            return op_negative_1(context);

        case opcode::op_1:
        case opcode::op_2:
        case opcode::op_3:
        case opcode::op_4:
        case opcode::op_5:
        case opcode::op_6:
        case opcode::op_7:
        case opcode::op_8:
        case opcode::op_9:
        case opcode::op_10:
        case opcode::op_11:
        case opcode::op_12:
        case opcode::op_13:
        case opcode::op_14:
        case opcode::op_15:
        case opcode::op_16:
            return op_n(context, op->code());

        // Executable codes.
        //---------------------------------------------------------------------

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
            context.reset(op);
            return true;

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

        case opcode::checklocktimeverify:
             return op_check_locktime_verify(context, script, tx, input_index);

        case opcode::nop:
        case opcode::nop1:
        ////case opcode::nop2:
        case opcode::nop3:
        case opcode::nop4:
        case opcode::nop5:
        case opcode::nop6:
        case opcode::nop7:
        case opcode::nop8:
        case opcode::nop9:
        case opcode::nop10:
            return op_nop(context);

        // Non-executable codes (should not be here).
        //---------------------------------------------------------------------

        case opcode::bad_operation:
            // Our test cases pass bad_operation into scripts, for example:
            // [if bad_operation else op_1 endif]
            report("Bad-operation sentinel is not exectuable.");
            return false;

        case opcode::raw_data:
            // Our test cases pass raw_data into scripts, for example:
            // [if raw_data else op_1 endif]
            report("Raw-data sentinel is not exectuable.");
            return false;

        default:
            // Our test cases pass these values into scripts, for example:
            // [if 188 else op_1 endif]
            report("Data is not exectuable.");
            return false;
    }
}

} // namespace chain
} // namespace libbitcoin
