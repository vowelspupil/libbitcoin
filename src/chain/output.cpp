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
#include <bitcoin/bitcoin/chain/output.hpp>

#include <cstdint>
#include <sstream>
#include <bitcoin/bitcoin/constants.hpp>
#include <bitcoin/bitcoin/utility/container_sink.hpp>
#include <bitcoin/bitcoin/utility/container_source.hpp>
#include <bitcoin/bitcoin/utility/istream_reader.hpp>
#include <bitcoin/bitcoin/utility/ostream_writer.hpp>

namespace libbitcoin {
namespace chain {

// This is a consensus critical value that must be set on reset.
const uint64_t output::not_found = sighash_null_value;

// This is a non-consensus sentinel used to indicate an output is unspent.
const uint32_t output::validation::not_spent = max_uint32;

// Constructors.
//-----------------------------------------------------------------------------

output::output()
  : value_(not_found), validation{}
{
}

output::output(output&& other)
  : output(other.value_, std::move(other.script_),
        other.validation.spender_height)
{
}

output::output(const output& other)
  : output(other.value_, other.script_, other.validation.spender_height)
{
}

// protected
output::output(uint64_t value, chain::script&& script, size_t spender_height)
  : value_(value), script_(std::move(script))
{
    validation.spender_height = spender_height;
}

// protected
output::output(uint64_t value, const chain::script& script,
    size_t spender_height)
  : value_(value), script_(script)
{
    validation.spender_height = spender_height;
}

output::output(uint64_t value, chain::script&& script)
  : value_(value), script_(std::move(script)), validation{}
{
}

output::output(uint64_t value, const chain::script& script)
  : value_(value), script_(script), validation{}
{
}

// Operators.
//-----------------------------------------------------------------------------

output& output::operator=(output&& other)
{
    value_ = other.value_;
    script_ = std::move(other.script_);
    return *this;
}

output& output::operator=(const output& other)
{
    value_ = other.value_;
    script_ = other.script_;
    return *this;
}

bool output::operator==(const output& other) const
{
    return (value_ == other.value_) && (script_ == other.script_);
}

bool output::operator!=(const output& other) const
{
    return !(*this == other);
}

// Deserialization.
//-----------------------------------------------------------------------------

output output::factory_from_data(const data_chunk& data, bool wire)
{
    output instance;
    instance.from_data(data, wire);
    return instance;
}

output output::factory_from_data(std::istream& stream, bool wire)
{
    output instance;
    instance.from_data(stream, wire);
    return instance;
}

output output::factory_from_data(reader& source, bool wire)
{
    output instance;
    instance.from_data(source, wire);
    return instance;
}

bool output::from_data(const data_chunk& data, bool wire)
{
    data_source istream(data);
    return from_data(istream, wire);
}

bool output::from_data(std::istream& stream, bool wire)
{
    istream_reader source(stream);
    return from_data(source, wire);
}

bool output::from_data(reader& source, bool wire)
{
    reset();

    if (!wire)
        validation.spender_height = source.read_4_bytes_little_endian();

    value_ = source.read_8_bytes_little_endian();
    script_.from_data(source, true);

    if (!source)
        reset();

    return source;
}

// protected
void output::reset()
{
    value_ = output::not_found;
    script_ = chain::script{};
}

// Empty scripts are valid, validation relies on not_found only.
bool output::is_valid() const
{
    return value_ != output::not_found;
}

// Serialization.
//-----------------------------------------------------------------------------

data_chunk output::to_data(bool wire) const
{
    data_chunk data;
    data.reserve(serialized_size(wire));
    data_sink ostream(data);
    to_data(ostream, wire);
    ostream.flush();
    BITCOIN_ASSERT(data.size() == serialized_size(wire));
    return data;
}

void output::to_data(std::ostream& stream, bool wire) const
{
    ostream_writer sink(stream);
    to_data(sink, wire);
}

void output::to_data(writer& sink, bool wire) const
{
    if (!wire)
    {
        auto height32 = safe_unsigned<uint32_t>(validation.spender_height);
        sink.write_4_bytes_little_endian(height32);
    }

    sink.write_8_bytes_little_endian(value_);
    script_.to_data(sink, true);
}

std::string output::to_string(uint32_t flags) const
{
    std::ostringstream text;

    text << "\tvalue = " << value_ << "\n"
        << "\t" << script_.to_string(flags) << "\n";

    return text.str();
}

// Size.
//-----------------------------------------------------------------------------

uint64_t output::serialized_size(bool wire) const
{
    // validation.spender_height is size_t stored as uint32_t.
    return (wire ? 0 : sizeof(uint32_t)) + sizeof(value_) +
        script_.serialized_size(true);
}

// Accessors.
//-----------------------------------------------------------------------------

uint64_t output::value() const
{
    return value_;
}

void output::set_value(uint64_t value)
{
    value_ = value;
}

chain::script& output::script()
{
    return script_;
}

const chain::script& output::script() const
{
    return script_;
}

void output::set_script(const chain::script& value)
{
    script_ = value;
}

void output::set_script(chain::script&& value)
{
    script_ = std::move(value);
}

// Validation helpers.
//-----------------------------------------------------------------------------

size_t output::signature_operations() const
{
    return script_.sigops(false);
}

} // namespace chain
} // namespace libbitcoin
