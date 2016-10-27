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
#include <bitcoin/bitcoin/chain/script/evaluation_context.hpp>

#include <cstddef>
#include <cstdint>
#include <utility>
#include <bitcoin/bitcoin/chain/script/script.hpp>
#include <bitcoin/bitcoin/constants.hpp>
#include <bitcoin/bitcoin/math/script_number.hpp>
#include <bitcoin/bitcoin/utility/data.hpp>

namespace libbitcoin {
namespace chain {
    
// Fixed tuning parameters.
static constexpr size_t stack_capactity = 42;
static constexpr size_t alternate_capactity = 42;
static constexpr size_t condition_capactity = 4;

// Constructors.
//-----------------------------------------------------------------------------

// Iterators must be set via run.
evaluation_context::evaluation_context(uint32_t flags)
  : op_count_(0), flags_(flags), condition(condition_capactity)
{
    alternate.reserve(alternate_capactity);
    stack.reserve(stack_capactity);
}

// Iterators must be set via run.
evaluation_context::evaluation_context(uint32_t flags, data_stack&& value)
  : op_count_(0), flags_(flags), condition(condition_capactity)
{
    alternate.reserve(alternate_capactity);
    stack.reserve(stack_capactity);
    stack = std::move(value);
}

// Iterators must be set via run.
evaluation_context::evaluation_context(uint32_t flags, const data_stack& value)
  : op_count_(0), flags_(flags), condition(condition_capactity)
{
    alternate.reserve(alternate_capactity);
    stack.reserve(stack_capactity);
    stack = value;
}

// Instructions.
//-----------------------------------------------------------------------------

// This does not clear the stacks.
bool evaluation_context::initialize(const script& script)
{
    // bit.ly/2c9HzmN
    if (script.satoshi_content_size() > max_script_size)
        return false;

    begin_ = script.operations().begin();
    end_ = script.operations().end();
    op_count_ = 0;
    return true;
}

void evaluation_context::reset(op_iterator instruction)
{
    begin_ = instruction;
}

// Operation count.
//-----------------------------------------------------------------------------

inline bool overflow_op_count(size_t count)
{
    return count > op_counter_limit;
}

bool evaluation_context::update_op_count(opcode code)
{
    // Addition is safe due to script size validation.
    if (!operation::is_push(code))
        ++op_count_;

    return !overflow_op_count(op_count_);
}

bool evaluation_context::update_pubkey_count(int32_t multisig_pubkeys)
{
    // bit.ly/2d1bsdB
    if (multisig_pubkeys < 0 || multisig_pubkeys > max_script_public_key_count)
        return false;

    // Addition is safe due to script size validation.
    op_count_ += multisig_pubkeys;
    return !overflow_op_count(op_count_);
}

// Properties.
//-----------------------------------------------------------------------------

evaluation_context::op_iterator evaluation_context::begin() const
{
    return begin_;
}

evaluation_context::op_iterator evaluation_context::end() const
{
    return end_;
}

uint32_t evaluation_context::flags() const
{
    return flags_;
}

/// Stack info.
//-----------------------------------------------------------------------------

data_chunk& evaluation_context::item(size_t index)
{
    return *position(index);
}

data_stack::iterator evaluation_context::position(size_t index)
{
    // Subtracting 1 makes back-index zero-based (unlike satoshi).
    BITCOIN_ASSERT(index < stack.size());
    return (stack.end() - 1) - index;
}

// bit.ly/2cowHlP
bool evaluation_context::is_stack_overflow() const
{
    // Addition is safe due to script size validation.
    return stack.size() + alternate.size() > max_stack_size;
}

bool evaluation_context::stack_result() const
{
    const auto& back = stack.back();
    if (stack.empty() || back.empty())
        return false;

    const auto last = back.end() - 1;

    // TODO: turn this into something understandble.
    for (auto it = back.begin(); it != back.end(); ++it)
        if (*it != 0)
            return !(it == last && *it == number::negative_mask);

    return false;
}

/// Stack pop.
//-----------------------------------------------------------------------------

// This call must be guarded.
data_chunk evaluation_context::pop()
{
    BITCOIN_ASSERT(!stack.empty());
    const auto value = stack.back();
    stack.pop_back();
    return value;
}

bool evaluation_context::pop(int32_t& out_value)
{
    number middle;
    if (!pop(middle))
        return false;

    out_value = middle.int32();
    return true;
}

bool evaluation_context::pop(number& out_number, size_t maxiumum_size)
{
    return !stack.empty() && out_number.set_data(pop(), maxiumum_size);
}

bool evaluation_context::pop_binary(number& first, number& second)
{
    // The right hand side number is at the top of the stack.
    return pop(first) && pop(second);
}

bool evaluation_context::pop_ternary(number& first, number& second,
    number& third)
{
    // The upper bound is at the top of the stack and the lower bound next.
    return pop(first) && pop(second) && pop(third);
}

// Determines if the value is a valid stack index and returns the index.
bool evaluation_context::pop_position(data_stack::iterator& out_position)
{
    int32_t index;
    if (!pop(index))
        return false;

    // Ensure the index is within bounds.
    const auto size = stack.size();
    if (index < 0 || index >= size)
        return false;

    out_position = position(static_cast<size_t>(index));
    return true;
}

// pop1/pop2/.../popi
bool evaluation_context::pop(data_stack& section, size_t count)
{
    if (stack.size() < count)
        return false;

    for (size_t i = 0; i < count; ++i)
        section.push_back(pop());

    return true;
}

/// Stack push.
//-----------------------------------------------------------------------------

// push
void evaluation_context::push(bool value)
{
    if (value)
        stack.emplace_back(number::positive_1);
    else
        stack.emplace_back();
}

// pop1/pop2/.../popi/pushi/.../push2/push1/pushi
void evaluation_context::duplicate(size_t index)
{
    stack.push_back(item(index));
}

// pop1/pop2/push1/push2
void evaluation_context::swap(size_t index_left, size_t index_right)
{
    std::swap(item(index_left), item(index_right));
}

} // namespace chain
} // namespace libbitcoin
