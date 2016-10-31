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

#include <cstdint>
#include <bitcoin/bitcoin/chain/point.hpp>
#include <bitcoin/bitcoin/constants.hpp>
////#include <bitcoin/bitcoin/utility/endian.hpp>
#include <bitcoin/bitcoin/utility/assert.hpp>

namespace libbitcoin {
namespace chain {

static const auto point_size = static_cast<uint8_t>(
    point::satoshi_fixed_size());

point_iterator::point_iterator()
  : point_iterator(empty_)
{
}

point_iterator::point_iterator(const point_iterator& other)
  : point_iterator(other.point_, other.current_)
{
}

point_iterator::point_iterator(const point& value, uint8_t index)
  : point_(value), current_(index)
{
}

point_iterator::operator bool() const
{
    return current_ < point_size;
}

// private
uint8_t point_iterator::current() const
{
    if (current_ < hash_size)
        return point_.hash()[current_];

    const auto position = current_ - hash_size;
    BITCOIN_ASSERT_MSG(position < sizeof(uint32_t), "increment failure");

    // TODO: move this little-endian iterator into endian.hpp.
    return static_cast<uint8_t>(point_.index() >> (position * byte_bits));
}

point_iterator::reference point_iterator::operator*() const
{
    return current();
}

point_iterator::pointer point_iterator::operator->() const
{
    return current();
}

bool point_iterator::operator==(const point_iterator& other) const
{
    return (current_ == other.current_) && (&point_ == &other.point_);
}

bool point_iterator::operator!=(const point_iterator& other) const
{
    return !(*this == other);
}

point_iterator point_iterator::operator+(uint8_t value) const
{
    const auto position = current_ < point_size ? current_ + 1 : current_;
    return point_iterator(point_, position);
}

point_iterator point_iterator::operator-(uint8_t value) const
{
    const auto position = current_ > 0 ? current_ - 1 : current_;
    return point_iterator(point_, position);
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
    if (current_ < point_size)
        current_++;
}

void point_iterator::decrement()
{
    if (current_ > 0)
        current_--;
}

} // namespace chain
} // namespace libbitcoin
