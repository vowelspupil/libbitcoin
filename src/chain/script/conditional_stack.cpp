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
#include <bitcoin/bitcoin/chain/script/conditional_stack.hpp>

#include <algorithm>
#include <bitcoin/bitcoin/utility/assert.hpp>

namespace libbitcoin {
namespace chain {

conditional_stack::conditional_stack(size_t initial_capacity)
{
    stack_.reserve(initial_capacity);
}

bool conditional_stack::closed() const
{
    return stack_.empty();
}

bool conditional_stack::succeeded() const
{
    const auto is_true = [](bool value) { return value; };
    return std::all_of(stack_.begin(), stack_.end(), is_true);
}

void conditional_stack::open(bool value)
{
    stack_.push_back(value);
}

void conditional_stack::clear()
{
    stack_.clear();
}

void conditional_stack::negate()
{
    BITCOIN_ASSERT(!stack_.empty());
    stack_.back() = !stack_.back();
}

void conditional_stack::close()
{
    BITCOIN_ASSERT(!stack_.empty());
    stack_.pop_back();
}

} // namespace chain
} // namespace libbitcoin
