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
#include <bitcoin/bitcoin/chain/script/operation.hpp>
#include <bitcoin/bitcoin/utility/assert.hpp>

namespace libbitcoin {
namespace chain {

operation_iterator::operation_iterator()
  : operation_iterator(empty_)
{
}

operation_iterator::operation_iterator(const operation_iterator& other)
  : operation_iterator(other.stack_, other.current_)
{
}

operation_iterator::operation_iterator(const opstack& value, size_t index)
  : stack_(value), current_(index)
{
}

operation_iterator::operator bool() const
{
    return current_ < stack_.size();
}

operation_iterator::reference operation_iterator::operator*() const
{
    return stack_[current_];
}

operation_iterator::pointer operation_iterator::operator->() const
{
    return &stack_[current_];
}

bool operation_iterator::operator==(const operation_iterator& other) const
{
    return (current_ == other.current_) && (&stack_ == &other.stack_);
}

bool operation_iterator::operator!=(const operation_iterator& other) const
{
    return !(*this == other);
}

operation_iterator operation_iterator::operator+(size_t value) const
{
    const auto position = current_ < stack_.size() ? current_ + 1 : current_;
    return operation_iterator(stack_, position);
}

operation_iterator operation_iterator::operator-(size_t value) const
{
    const auto position = current_ > 0 ? current_ - 1 : current_;
    return operation_iterator(stack_, position);
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

operation_iterator::iterator& operation_iterator::operator--()
{
    decrement();
    return *this;
}

operation_iterator::iterator operation_iterator::operator--(int)
{
    auto it = *this;
    decrement();
    return it;
}

void operation_iterator::increment()
{
    if (current_ < stack_.size())
        current_++;
}

void operation_iterator::decrement()
{
    if (current_ > 0)
        current_--;
}

} // namespace chain
} // namespace libbitcoin
