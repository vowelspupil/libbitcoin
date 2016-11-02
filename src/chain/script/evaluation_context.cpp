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
#include <bitcoin/bitcoin/chain/script/operation.hpp>
#include <bitcoin/bitcoin/chain/script/script.hpp>
#include <bitcoin/bitcoin/constants.hpp>
#include <bitcoin/bitcoin/math/script_number.hpp>
#include <bitcoin/bitcoin/utility/data.hpp>

namespace libbitcoin {
namespace chain {
    
// Fixed tuning parameters, max_stack_size ensures no reallocation.
static constexpr size_t stack_capactity = max_stack_size;
static constexpr size_t alternate_capactity = max_stack_size;
static constexpr size_t condition_capactity = max_stack_size;

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
bool evaluation_context::set_script(const script& script)
{
    // bit.ly/2c9HzmN
    if (script.satoshi_content_size() > max_script_size)
        return false;

    begin_ = script.begin();
    jump_ = script.begin();
    end_ = script.end();
    op_count_ = 0;
    return true;
}

void evaluation_context::set_jump(operation::const_iterator instruction)
{
    // The begin_ member could be overloaded for this since it is never reused.
    // But the cost of the proper abstraction is just a few bytes.
    jump_ = instruction;
}

// Operation count.
//-----------------------------------------------------------------------------

inline bool operation_overflow(size_t count)
{
    return count > max_counted_ops;
}

bool evaluation_context::update_operation_count(const operation& op)
{
    // Addition is safe due to script size validation.
    if (operation::is_counted(op.code()))
        ++op_count_;

    return !operation_overflow(op_count_);
}

bool evaluation_context::update_pubkey_count(int32_t multisig_pubkeys)
{
    // bit.ly/2d1bsdB
    if (multisig_pubkeys < 0 || multisig_pubkeys > max_script_public_key_count)
        return false;

    // Addition is safe due to script size validation.
    op_count_ += multisig_pubkeys;
    return !operation_overflow(op_count_);
}

// Properties.
//-----------------------------------------------------------------------------

operation::const_iterator evaluation_context::begin() const
{
    return begin_;
}

operation::const_iterator evaluation_context::jump() const
{
    return jump_;
}

operation::const_iterator evaluation_context::end() const
{
    return end_;
}

uint32_t evaluation_context::flags() const
{
    return flags_;
}

/// Stack info.
//-----------------------------------------------------------------------------

const data_stack::value_type& evaluation_context::item(size_t index) const
{
    return *position(index);
}

data_stack::const_iterator evaluation_context::position(size_t index) const
{
    // Subtracting 1 makes the stack indexes zero-based (unlike satoshi).
    BITCOIN_ASSERT(index < stack.size());
    return (stack.end() - 1) - index;
}

bool evaluation_context::is_short_circuited(const operation& op) const
{
    return !(operation::is_conditional(op.code()) || condition.succeeded());
}

bool evaluation_context::is_stack_overflow() const
{
    // bit.ly/2cowHlP
    // Addition is safe due to script size validation.
    return stack.size() + alternate.size() > max_stack_size;
}

// private
bool evaluation_context::stack_to_bool() const
{
    const auto& back = stack.back();
    if (back.empty())
        return false;

    const auto last = back.end() - 1;
    for (auto it = back.begin(); it != back.end(); ++it)
    {
        if (*it != 0)
        {
            // It's not non-zero it's the terminating negative sentinel.
            return !(it == last && *it == number::negative_0);
        }
    }

    return false;
}

// This call must be guarded.
bool evaluation_context::stack_state() const
{
    BITCOIN_ASSERT(!stack.empty());
    return stack_to_bool();
}

// This call is safe.
bool evaluation_context::stack_result() const
{
    return !stack.empty() && stack_to_bool();
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
    // The upper bound is at stack top, lower bound next, value next.
    return pop(first) && pop(second) && pop(third);
}

// Determines if popped value is valid post-pop stack index and returns index.
bool evaluation_context::pop_position(data_stack::const_iterator& out_position)
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
        stack.push_back({ number::positive_1 });
    else
        stack.push_back({});
}

// pop1/pop2/.../popi/pushi/.../push2/push1/pushi
void evaluation_context::duplicate(size_t index)
{
    stack.push_back(item(index));
}

// pop1/pop2/push1/push2
void evaluation_context::swap(size_t index_left, size_t index_right)
{
    // TODO: refactor to allow DRY without const_cast here.
    std::swap(
        const_cast<data_stack::value_type&>(item(index_left)),
        const_cast<data_stack::value_type&>(item(index_right)));
}

} // namespace chain
} // namespace libbitcoin
