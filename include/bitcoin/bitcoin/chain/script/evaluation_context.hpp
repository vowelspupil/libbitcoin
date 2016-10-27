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
#include <bitcoin/bitcoin/define.hpp>
#include <bitcoin/bitcoin/utility/data.hpp>

namespace libbitcoin {
namespace chain {

class BC_API script;

class evaluation_context
{
public:
    typedef operation::stack::const_iterator iterator;

    evaluation_context(uint32_t flags);
    evaluation_context(uint32_t flags, size_t, data_stack&& value);
    evaluation_context(uint32_t flags, const data_stack& value);

    bool evaluate(const script& script);
    void reset(iterator instruction);
    iterator begin() const;
    iterator end() const;
    uint32_t flags() const;
    data_chunk pop_stack();
    bool stack_result() const;
    bool is_stack_overflow() const;
    bool update_op_count(opcode code);
    bool update_pubkey_count(int32_t multisig_pubkeys);

    // public stacks
    data_stack stack;
    data_stack alternate;
    conditional_stack condition;

private:
    iterator begin_;
    iterator end_;
    size_t op_count_;
    const uint32_t flags_;
};

} // namespace chain
} // namespace libbitcoin

#endif
