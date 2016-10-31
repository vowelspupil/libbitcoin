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
#ifndef LIBBITCOIN_CHAIN_OPERATION_STACK_HPP
#define LIBBITCOIN_CHAIN_OPERATION_STACK_HPP

#include <cstdint>
#include <initializer_list>
#include <vector>
#include <bitcoin/bitcoin/chain/script/operation.hpp>
#include <bitcoin/bitcoin/define.hpp>
#include <bitcoin/bitcoin/math/elliptic_curve.hpp>
#include <bitcoin/bitcoin/utility/data.hpp>
#include <bitcoin/bitcoin/math/hash.hpp>

namespace libbitcoin {
namespace chain {

class BC_API operation_stack
{
public:
    // Factories.
    //-------------------------------------------------------------------------

    static operation_stack to_null_data_pattern(data_slice data);
    static operation_stack to_pay_public_key_pattern(data_slice point);
    static operation_stack to_pay_key_hash_pattern(const short_hash& hash);
    static operation_stack to_pay_script_hash_pattern(const short_hash& hash);
    static operation_stack to_pay_multisig_pattern(uint8_t signatures,
        const point_list& points);
    static operation_stack to_pay_multisig_pattern(uint8_t signatures,
        const data_stack& points);

    // Constructors.
    //-------------------------------------------------------------------------

    operation_stack();
    operation_stack(operation_stack&& other);
    operation_stack(const operation_stack& other);
    operation_stack(std::initializer_list<operation>&& list);
    operation_stack(const std::initializer_list<operation>& list);

    // Operators.
    //-------------------------------------------------------------------------

    /// This class is move assignable and copy assignable.
    operation_stack& operator=(operation_stack&& other);
    operation_stack& operator=(const operation_stack& other);

    bool operator==(const operation_stack& other) const;
    bool operator!=(const operation_stack& other) const;

    operation& operator[](std::size_t index);
    const operation& operator[](std::size_t index) const;

    // Iteration.
    //-------------------------------------------------------------------------

    operation_iterator begin() const;
    operation_iterator end() const;

    // Vector.
    //-------------------------------------------------------------------------

    void clear();
    bool empty() const;
    size_t size() const;
    void shrink_to_fit();
    void resize(size_t size);
    void reserve(size_t size);
    const operation& back() const;
    const operation& front() const;
    void push_back(operation&& op);
    void push_back(const operation& op);

private:
    std::vector<operation> stack_;
};

} // end chain
} // end libbitcoin

#endif
