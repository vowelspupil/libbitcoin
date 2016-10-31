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
#include <vector>
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

    operation_iterator();
    operation_iterator(const operation_iterator& other);
    operation_iterator(const opstack& value, size_t index = 0);

    operator bool() const;

    reference operator*() const;
    pointer operator->() const;

    bool operator==(const operation_iterator& other) const;
    bool operator!=(const operation_iterator& other) const;
    operation_iterator operator+(const size_t value) const;
    operation_iterator operator-(const size_t value) const;

    operation_iterator& operator++();
    operation_iterator operator++(int);
    operation_iterator& operator--();
    operation_iterator operator--(int);

protected:
    void increment();
    void decrement();

private:
    static const opstack empty_;
    const opstack& stack_;
    size_t current_;
};

} // namespace chain
} // namespace libbitcoin

#endif
