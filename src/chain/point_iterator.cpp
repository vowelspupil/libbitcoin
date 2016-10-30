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
#include <bitcoin/bitcoin/chain/point_iterator.hpp>

#include <bitcoin/bitcoin/constants.hpp>
#include <bitcoin/bitcoin/chain/point.hpp>
#include <bitcoin/bitcoin/utility/endian.hpp>

namespace libbitcoin {
namespace chain {

static constexpr uint8_t max_offset = hash_size + sizeof(uint32_t);

point_iterator::point_iterator(const point& value)
  : point_(value), offset_(0)
{
}

point_iterator::point_iterator(const point& value, bool end)
  : point_(value), offset_(end ? max_offset : 0)
{
}

point_iterator::point_iterator(const point& value, uint8_t offset)
  : point_(value), offset_(offset)
{
}

point_iterator::point_iterator(const point_iterator& other)
  : point_iterator(other.point_, other.offset_)
{
}

point_iterator::operator bool() const
{
    return (offset_ < max_offset);
}

// private
uint8_t point_iterator::current() const
{
    if (offset_ < hash_size)
        return point_.hash()[offset_];

    const auto position = offset_ - hash_size;

    // TODO: move this little-endian iterator into endian.hpp.
    return position >= sizeof(uint32_t) ? 0 :
        static_cast<uint8_t>(point_.index() >> (position * byte_bits));
}

point_iterator::reference point_iterator::operator*() const
{
    return current();
}

point_iterator::pointer point_iterator::operator->() const
{
    return current();
}

bool point_iterator::operator==(const iterator& other) const
{
    return (&point_ == &other.point_) && (offset_ == other.offset_);
}

bool point_iterator::operator!=(const iterator& other) const
{
    return !(*this == other);
}

point_iterator::iterator& point_iterator::operator++()
{
    increment();
    return *this;
}

point_iterator::iterator point_iterator::operator++(int)
{
    auto it = *this;
    increment();
    return it;
}

point_iterator::iterator& point_iterator::operator--()
{
    decrement();
    return *this;
}

point_iterator::iterator point_iterator::operator--(int)
{
    auto it = *this;
    decrement();
    return it;
}

void point_iterator::increment()
{
    if (offset_ < max_offset)
        offset_++;
}

void point_iterator::decrement()
{
    if (offset_ > 0)
        offset_--;
}

} // namespace chain
} // namespace libbitcoin
