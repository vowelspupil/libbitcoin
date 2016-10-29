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
#include <bitcoin/bitcoin/chain/script/operation_iterator.hpp>

#include <cstddef>
#include <memory>
#include <bitcoin/bitcoin/constants.hpp>
#include <bitcoin/bitcoin/chain/script/operation.hpp>
#include <bitcoin/bitcoin/utility/data.hpp>

namespace libbitcoin {
namespace chain {

operation_iterator::operation_iterator(const data_chunk& value)
    : operation_iterator(value, false)
{
}

operation_iterator::operation_iterator(const data_chunk& value, bool end)
  : operation_iterator(value, end ? max_size_t : 0)
{
}

operation_iterator::operation_iterator(const data_chunk& value, size_t offset)
  : bytes_(value), stream_(bytes_), source_(stream_), offset_(offset),
    current_(std::make_shared<value_type>())
{
    source_.skip(offset);
}

operation_iterator::operation_iterator(const operation_iterator& other)
  : operation_iterator(other.bytes_, other.offset_)
{
}

operation_iterator::operator bool() const
{
    return !source_.is_exhausted();
}

operation_iterator::reference operation_iterator::operator*() const
{
    return *current_;
}

operation_iterator::pointer operation_iterator::operator->() const
{
    return *current_;
}

bool operation_iterator::operator==(const iterator& other) const
{
    // Use only offset for end comparison (optimization).
    return /*(bytes_ == other.bytes_) &&*/ (offset_ == other.offset_);
}

bool operation_iterator::operator!=(const iterator& other) const
{
    return !(*this == other);
}

operation_iterator::iterator& operation_iterator::operator++()
{
    increment();
    return *this;
}

operation_iterator::iterator operation_iterator::operator++(int)
{
    auto it = *this;
    increment();
    return it;
}

void operation_iterator::increment()
{
    // The offset is maintained for comparison and copy construction.
    // It is essential that operation uses same opcode through read/size/write.
    if (current_->from_data(source_))
        offset_ += current_->serialized_size();
    else
        offset_ = max_size_t;
}

} // namespace chain
} // namespace libbitcoin
