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
#include <bitcoin/bitcoin/chain/script/operation_stack.hpp>

#include <cstddef>
#include <initializer_list>
#include <utility>
#include <bitcoin/bitcoin/chain/script/opcode.hpp>
#include <bitcoin/bitcoin/chain/script/operation_iterator.hpp>
#include <bitcoin/bitcoin/chain/script/script.hpp>

namespace libbitcoin {
namespace chain {
    
// Factories.
//-----------------------------------------------------------------------------

operation_stack operation_stack::to_null_data_pattern(data_slice data)
{
    if (data.size() > script::max_null_data_size)
        return{};

    return operation_stack
    {
        operation{ opcode::return_ },
        operation{ to_chunk(data) }
    };
}

operation_stack operation_stack::to_pay_public_key_pattern(data_slice point)
{
    if (!is_public_key(point))
        return{};

    return operation_stack
    {
        { to_chunk(point) },
        { opcode::checksig }
    };
}

operation_stack operation_stack::to_pay_key_hash_pattern(
    const short_hash& hash)
{
    return operation_stack
    {
        { opcode::dup },
        { opcode::hash160 },
        { to_chunk(hash) },
        { opcode::equalverify },
        { opcode::checksig }
    };
}

operation_stack operation_stack::to_pay_script_hash_pattern(
    const short_hash& hash)
{
    return operation_stack
    {
        { opcode::hash160 },
        { to_chunk(hash) },
        { opcode::equal }
    };
}

operation_stack operation_stack::to_pay_multisig_pattern(uint8_t signatures,
    const point_list& points)
{
    const auto conversion = [](const ec_compressed& point)
    {
        return to_chunk(point);
    };

    data_stack chunks(points.size());
    std::transform(points.begin(), points.end(), chunks.begin(), conversion);
    return to_pay_multisig_pattern(signatures, chunks);
}

operation_stack operation_stack::to_pay_multisig_pattern(uint8_t signatures,
    const data_stack& points)
{
    static constexpr auto op_81 = static_cast<uint8_t>(opcode::push_positive_1);
    static constexpr auto op_96 = static_cast<uint8_t>(opcode::push_positive_16);
    static constexpr auto zero = op_81 - 1;
    static constexpr auto max = op_96 - zero;

    const auto m = signatures;
    const auto n = points.size();

    if (m < 1 || m > n || n < 1 || n > max)
        return operation_stack();

    const auto op_m = static_cast<opcode>(m + zero);
    const auto op_n = static_cast<opcode>(points.size() + zero);

    operation_stack ops;
    ops.reserve(points.size() + 3);
    ops.push_back({ op_m });

    for (const auto point: points)
    {
        if (!is_public_key(point))
            return{};

        ops.push_back(point);
    }

    ops.push_back({ op_n });
    ops.push_back({ opcode::checkmultisig });
    return ops;
}

// Constructors.
//-----------------------------------------------------------------------------

operation_stack::operation_stack()
{
}

operation_stack::operation_stack(operation_stack&& other)
  : stack_(std::move(other.stack_))
{
}

operation_stack::operation_stack(const operation_stack& other)
  : stack_(other.stack_)
{
}

operation_stack::operation_stack(const std::initializer_list<operation>& list)
  : stack_(list)
{
}

operation_stack::operation_stack(std::initializer_list<operation>&& list)
  : stack_(std::move(list))
{
}

// Operators.
//-----------------------------------------------------------------------------

operation_stack& operation_stack::operator=(operation_stack&& other)
{
    stack_ = std::move(other.stack_);
    return *this;
}

operation_stack& operation_stack::operator=(const operation_stack& other)
{
    stack_ = other.stack_;
    return *this;
}

bool operation_stack::operator==(const operation_stack& other) const
{
    return stack_ == other.stack_;
}

bool operation_stack::operator!=(const operation_stack& other) const
{
    return !(*this == other);
}

operation& operation_stack::operator[](std::size_t index)
{
    return stack_[index];
}

const operation& operation_stack::operator[](std::size_t index) const
{
    return stack_[index];
}

// Iteration.
//-----------------------------------------------------------------------------

operation_iterator operation_stack::begin() const
{
    // The first stack access must be method-based to guarantee the cache.
    return operation_iterator(*this);
}

operation_iterator operation_stack::end() const
{
    // The first stack access must be method-based to guarantee the cache.
    return operation_iterator(*this, size());
}

// Vector.
//-----------------------------------------------------------------------------

void operation_stack::clear()
{
    stack_.clear();
}

bool operation_stack::empty() const
{
    return stack_.empty();
}

size_t operation_stack::size() const
{
    return stack_.size();
}

void operation_stack::shrink_to_fit()
{
    stack_.shrink_to_fit();
}

void operation_stack::resize(size_t size)
{
    stack_.resize(size);
}

void operation_stack::reserve(size_t size)
{
    stack_.reserve(size);
}

const operation& operation_stack::back() const
{
    return stack_.back();
}

const operation& operation_stack::front() const
{
    return stack_.front();
}

void operation_stack::push_back(operation&& op)
{
    stack_.push_back(std::move(op));
}

void operation_stack::push_back(const operation& op)
{
    stack_.push_back(op);
}

} // namespace chain
} // namespace libbitcoin
