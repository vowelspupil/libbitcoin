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
#include <bitcoin/bitcoin/message/headers.hpp>

#include <algorithm>
#include <cstdint>
#include <initializer_list>
#include <istream>
#include <utility>
#include <bitcoin/bitcoin/math/limits.hpp>
#include <bitcoin/bitcoin/message/inventory.hpp>
#include <bitcoin/bitcoin/message/inventory_vector.hpp>
#include <bitcoin/bitcoin/message/version.hpp>
#include <bitcoin/bitcoin/utility/container_sink.hpp>
#include <bitcoin/bitcoin/utility/container_source.hpp>
#include <bitcoin/bitcoin/utility/istream_reader.hpp>
#include <bitcoin/bitcoin/utility/ostream_writer.hpp>

namespace libbitcoin {
namespace message {

const std::string headers::command = "headers";
const uint32_t headers::version_minimum = version::level::headers;
const uint32_t headers::version_maximum = version::level::maximum;

headers headers::factory_from_data(uint32_t version,
    const data_chunk& data)
{
    headers instance;
    instance.from_data(version, data);
    return instance;
}

headers headers::factory_from_data(uint32_t version,
    std::istream& stream)
{
    headers instance;
    instance.from_data(version, stream);
    return instance;
}

headers headers::factory_from_data(uint32_t version,
    reader& source)
{
    headers instance;
    instance.from_data(version, source);
    return instance;
}

headers::headers()
  : elements_()
{
}

// Uses headers copy assignment.
headers::headers(const header_message::list& values)
  : elements_(values)
{
}

headers::headers(header_message::list&& values)
  : elements_(std::move(values))
{
}

headers::headers(const std::initializer_list<header_message>& values)
  : elements_(values)
{
}

headers::headers(const headers& other)
  : headers(other.elements_)
{
}

headers::headers(headers&& other)
  : headers(std::move(other.elements_))
{
}

bool headers::is_valid() const
{
    return !elements_.empty();
}

void headers::reset()
{
    elements_.clear();
    elements_.shrink_to_fit();
}

bool headers::from_data(uint32_t version, const data_chunk& data)
{
    data_source istream(data);
    return from_data(version, istream);
}

bool headers::from_data(uint32_t version, std::istream& stream)
{
    istream_reader source(stream);
    return from_data(version, source);
}

bool headers::from_data(uint32_t version, reader& source)
{
    reset();

    elements_.resize(source.read_size_little_endian());

    for (auto& element: elements_)
        if (!element.from_data(version, source))
            break;

    if (version < headers::version_minimum)
        source.invalidate();

    if (!source)
        reset();

    return source;
}

data_chunk headers::to_data(uint32_t version) const
{
    data_chunk data;
    data.reserve(serialized_size(version));
    data_sink ostream(data);
    to_data(version, ostream);
    ostream.flush();
    BITCOIN_ASSERT(data.size() == serialized_size(version));
    return data;
}

void headers::to_data(uint32_t version, std::ostream& stream) const
{
    ostream_writer sink(stream);
    to_data(version, sink);
}

void headers::to_data(uint32_t version, writer& sink) const
{
    sink.write_variable_little_endian(elements_.size());

    for (const auto& element: elements_)
        element.to_data(version, sink);
}

void headers::to_hashes(hash_list& out) const
{
    const auto map = [](const header_message& header)
    {
        return header.hash();
    };

    out.resize(elements_.size());
    std::transform(elements_.begin(), elements_.end(), out.begin(), map);
}

void headers::to_inventory(inventory_vector::list& out,
    inventory::type_id type) const
{
    const auto map = [type](const header_message& header)
    {
        return inventory_vector{ type, header.hash() };
    };

    std::transform(elements_.begin(), elements_.end(), std::back_inserter(out), map);
}

uint64_t headers::serialized_size(uint32_t version) const
{
    return variable_uint_size(elements_.size()) +
        (elements_.size() * header_message::satoshi_fixed_size(version));
}

header_message::list& headers::elements()
{
    return elements_;
}

const header_message::list& headers::elements() const
{
    return elements_;
}

void headers::set_elements(const header_message::list& values)
{
    elements_ = values;
}

void headers::set_elements(header_message::list&& values)
{
    elements_ = std::move(values);
}

headers& headers::operator=(headers&& other)
{
    elements_ = std::move(other.elements_);
    return *this;
}

bool headers::operator==(const headers& other) const
{
    return (elements_ == other.elements_);
}

bool headers::operator!=(const headers& other) const
{
    return !(*this == other);
}

} // namespace message
} // namespace libbitcoin
