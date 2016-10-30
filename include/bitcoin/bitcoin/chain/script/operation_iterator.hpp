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
#include <memory>
#include <bitcoin/bitcoin/define.hpp>
#include <bitcoin/bitcoin/utility/container_source.hpp>
#include <bitcoin/bitcoin/utility/data.hpp>
#include <bitcoin/bitcoin/utility/istream_reader.hpp>

namespace libbitcoin {
namespace chain {

class operation;

class BC_API operation_iterator
{
public:
    typedef operation* pointer;
    typedef operation& reference;
    typedef operation value_type;
    typedef ptrdiff_t difference_type;
    typedef std::forward_iterator_tag iterator_category;

    typedef operation_iterator iterator;
    typedef operation_iterator const_iterator;

    // constructors
    operation_iterator();
    operation_iterator(const data_chunk& value);
    operation_iterator(const data_chunk& value, bool end);
    operation_iterator(const data_chunk& value, size_t offset);
    operation_iterator(const operation_iterator& other);

    operator bool() const;

    // iterator methods
    reference operator*() const;
    pointer operator->() const;

    bool operator==(const iterator& other) const;
    bool operator!=(const iterator& other) const;

    iterator& operator++();
    iterator operator++(int);

protected:
    void increment();

private:
    const data_chunk empty_;
    const data_chunk& bytes_;
    data_source stream_;
    istream_reader source_;
    size_t offset_;

    // This is a cache within the iterator.
    // Pointer breaks declaration cycle.
    std::shared_ptr<value_type> current_;
};

} // namespace chain
} // namespace libbitcoin

#endif
