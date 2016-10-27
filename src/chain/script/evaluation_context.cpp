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
    
static constexpr size_t stack_capactity = 42;
static constexpr size_t alternate_capactity = 42;
static constexpr size_t condition_capactity = 4;

// Iterators must be set via run.
evaluation_context::evaluation_context(uint32_t flags)
  : op_count_(0), flags_(flags), condition(condition_capactity)
{
    alternate.reserve(alternate_capactity);
    stack.reserve(stack_capactity);
}

// Iterators must be set via run.
evaluation_context::evaluation_context(uint32_t flags, size_t, data_stack&& value)
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

// This does not clear the stacks.
bool evaluation_context::initialize(const script& script)
{
    // bit.ly/2c9HzmN
    if (script.satoshi_content_size() > max_script_size)
        return false;

    op_count_ = 0;
    const auto& operations = script.operations();
    begin_ = operations.begin();
    end_ = operations.end();
    return true;
}

void evaluation_context::reset(iterator instruction)
{
    begin_ = instruction;
}

evaluation_context::iterator evaluation_context::begin() const
{
    return begin_;
}

evaluation_context::iterator evaluation_context::end() const
{
    return end_;
}

uint32_t evaluation_context::flags() const
{
    return flags_;
}

data_chunk evaluation_context::pop_stack()
{
    const auto value = stack.back();
    stack.pop_back();
    return value;
}

// bit.ly/2cowHlP
bool evaluation_context::is_stack_overflow() const
{
    // Addition is safe due to script size validation.
    return stack.size() + alternate.size() > max_stack_size;
}

bool evaluation_context::stack_result() const
{
    if (stack.empty() || stack.back().empty())
        return false;

    const auto& back = stack.back();
    const auto last_position = back.end() - 1;

    for (auto it = back.begin(); it != back.end(); ++it)
        if (*it != 0)
            return !(it == last_position &&
                *it == script_number::negative_mask);

    return false;
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


} // namespace chain
} // namespace libbitcoin
