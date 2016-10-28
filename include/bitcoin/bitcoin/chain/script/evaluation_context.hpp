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
#ifndef LIBBITCOIN_CHAIN_EVALUATION_CONTEXT_HPP
#define LIBBITCOIN_CHAIN_EVALUATION_CONTEXT_HPP

#include <cstdint>
#include <bitcoin/bitcoin/chain/script/conditional_stack.hpp>
#include <bitcoin/bitcoin/chain/script/opcode.hpp>
#include <bitcoin/bitcoin/chain/script/operation.hpp>
#include <bitcoin/bitcoin/constants.hpp>
#include <bitcoin/bitcoin/define.hpp>
#include <bitcoin/bitcoin/math/script_number.hpp>
#include <bitcoin/bitcoin/utility/data.hpp>

namespace libbitcoin {
namespace chain {

// All index parameters are zero-based and relative to stack top.
class BC_API script;

class evaluation_context
{
public:
    typedef script_number number;
    typedef operation::stack::const_iterator op_iterator;

    /// Constructors.
    evaluation_context(uint32_t flags);
    evaluation_context(uint32_t flags, data_stack&& value);
    evaluation_context(uint32_t flags, const data_stack& value);

    /// Instructions.
    bool initialize(const script& script);
    void reset(op_iterator instruction);

    /// Operation count.
    bool update_op_count(const operation& op);
    bool update_pubkey_count(int32_t multisig_pubkeys);

    /// Properties.
    op_iterator begin() const;
    op_iterator end() const;
    uint32_t flags() const;

    /// Stack info.
    data_chunk& item(size_t index);
    data_stack::iterator position(size_t index);
    bool is_short_circuited(const operation& op) const;
    bool is_stack_overflow() const;
    bool stack_result() const;

    /// Stack pop.
    data_chunk pop();
    bool pop(data_stack& section, size_t count);
    bool pop(int32_t& out_value);
    bool pop(number& out_number, size_t maxiumum_size=max_number_size);
    bool pop_binary(number& first, number& second);
    bool pop_ternary(number& first, number& second, number& third);
    bool pop_position(data_stack::iterator& out_position);

    /// Stack push.
    void push(bool value);
    void duplicate(size_t index);
    void swap(size_t index_left, size_t index_right);

    /// Stacks.
    /// TODO: make private.
    data_stack stack;
    data_stack alternate;
    conditional_stack condition;

private:
    op_iterator begin_;
    op_iterator end_;
    size_t op_count_;
    const uint32_t flags_;
};

} // namespace chain
} // namespace libbitcoin

#endif
