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
#include <bitcoin/bitcoin/message/block.hpp>

#include <cstdint>
#include <cstddef>
#include <istream>
#include <utility>
#include <bitcoin/bitcoin/message/version.hpp>
#include <bitcoin/bitcoin/chain/header.hpp>
#include <bitcoin/bitcoin/chain/transaction.hpp>
#include <bitcoin/bitcoin/utility/data.hpp>
#include <bitcoin/bitcoin/utility/reader.hpp>

namespace libbitcoin {
namespace message {

const std::string block::command = "block";
const uint32_t block::version_minimum = version::level::minimum;
const uint32_t block::version_maximum = version::level::maximum;

block block::factory_from_data(uint32_t version, const data_chunk& data)
{
    block instance;
    instance.from_data(version, data);
    return instance;
}

block block::factory_from_data(uint32_t version, std::istream& stream)
{
    block instance;
    instance.from_data(version, stream);
    return instance;
}

block block::factory_from_data(uint32_t version, reader& source)
{
    block instance;
    instance.from_data(version, source);
    return instance;
}

block::block()
  : chain::block(), originator_(0)
{
}

block::block(block&& other)
  : chain::block(std::move(other)),
    originator_(other.originator_)
{
}

block::block(const block& other)
  : chain::block(other), originator_(other.originator_)
{
}

block::block(chain::block&& other)
  : chain::block(std::move(other)), originator_(0)
{
}

block::block(const chain::block& other)
  : chain::block(other), originator_(0)
{
}

block::block(chain::header&& header, chain::transaction::list&& transactions)
  : chain::block(std::move(header), std::move(transactions)),
    originator_(0)
{
}

block::block(const chain::header& header,
    const chain::transaction::list& transactions)
  : chain::block(header, transactions), originator_(0)
{
}

bool block::from_data(uint32_t, const data_chunk& data)
{
    return chain::block::from_data(data);
}

bool block::from_data(uint32_t, std::istream& stream)
{
    return chain::block::from_data(stream);
}

bool block::from_data(uint32_t, reader& source)
{
    return chain::block::from_data(source);
}

data_chunk block::to_data(uint32_t) const
{
    return chain::block::to_data();
}

void block::to_data(uint32_t, std::ostream& stream) const
{
    chain::block::to_data(stream);
}

void block::to_data(uint32_t, writer& sink) const
{
    chain::block::to_data(sink);
}

size_t block::serialized_size(uint32_t) const
{
    return chain::block::serialized_size();
}

uint64_t block::originator() const
{
    return originator_;
}

void block::set_originator(uint64_t value) const
{
    originator_ = value;
}

block& block::operator=(chain::block&& other)
{
    reset();
    chain::block::operator=(std::move(other));
    return *this;
}

block& block::operator=(block&& other)
{
    originator_ = other.originator_;
    chain::block::operator=(std::move(other));
    return *this;
}

bool block::operator==(const chain::block& other) const
{
    return chain::block::operator==(other);
}

bool block::operator!=(const chain::block& other) const
{
    return chain::block::operator!=(other);
}

bool block::operator==(const block& other) const
{
    return chain::block::operator==(other);
}

bool block::operator!=(const block& other) const
{
    return !(*this == other);
}

} // namespace message
} // namespace libbitcoin
