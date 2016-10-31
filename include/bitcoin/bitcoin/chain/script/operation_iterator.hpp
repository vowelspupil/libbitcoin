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
#ifndef LIBBITCOIN_CHAIN_OPERATION_ITERATOR_HPP
#define LIBBITCOIN_CHAIN_OPERATION_ITERATOR_HPP

#include <cstddef>
#include <iterator>
#include <bitcoin/bitcoin/define.hpp>

namespace libbitcoin {
namespace chain {

class operation;
class operation_stack;

class BC_API operation_iterator
{
public:
    typedef const operation* pointer;
    typedef const operation& reference;
    typedef operation value_type;
    typedef ptrdiff_t difference_type;
    typedef std::bidirectional_iterator_tag iterator_category;

    typedef operation_iterator iterator;
    typedef operation_iterator const_iterator;

    // Constructors.
    //-------------------------------------------------------------------------

    operation_iterator();
    operation_iterator(const operation_iterator& other);
    operation_iterator(const operation_stack& value, size_t index=0);

    // Operators.
    //-------------------------------------------------------------------------

    operator bool() const;
    reference operator*() const;
    pointer operator->() const;
    operation_iterator& operator++();
    operation_iterator operator++(int);
    operation_iterator& operator--();
    operation_iterator operator--(int);
    operation_iterator operator+(const int value) const;
    operation_iterator operator-(const int value) const;
    bool operator==(const operation_iterator& other) const;
    bool operator!=(const operation_iterator& other) const;

    /// The iterator may only be assigned to another of the same point.
    operation_iterator& operator=(const operation_iterator& other);

protected:
    void increment();
    void decrement();
    operation_iterator increase(size_t value) const;
    operation_iterator decrease(size_t value) const;

private:
    static const operation_stack empty_;
    const operation_stack& stack_;
    size_t current_;
};

} // namespace chain
} // namespace libbitcoin

#endif
