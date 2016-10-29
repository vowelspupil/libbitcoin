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
#include <bitcoin/bitcoin/chain/input.hpp>

#include <sstream>
#include <bitcoin/bitcoin/constants.hpp>
#include <bitcoin/bitcoin/utility/container_sink.hpp>
#include <bitcoin/bitcoin/utility/container_source.hpp>
#include <bitcoin/bitcoin/utility/istream_reader.hpp>
#include <bitcoin/bitcoin/utility/ostream_writer.hpp>

namespace libbitcoin {
namespace chain {

static constexpr auto use_length_prefix = true;

// Constructors.
//-----------------------------------------------------------------------------

input::input()
  : previous_output_(), sequence_{0}
{
}

input::input(input&& other)
  : input(std::move(other.previous_output_), std::move(other.script_),
      other.sequence_)
{
}

input::input(const input& other)
  : input(other.previous_output_, other.script_, other.sequence_)
{
}

input::input(output_point&& previous_output, chain::script&& script,
    uint32_t sequence)
  : previous_output_(std::move(previous_output)), script_(std::move(script)),
    sequence_(sequence)
{
}

input::input(const output_point& previous_output, const chain::script& script,
    uint32_t sequence)
  : previous_output_(previous_output), script_(script), sequence_(sequence)
{
}

// Operators.
//-----------------------------------------------------------------------------

input& input::operator=(const input& other)
{
    previous_output_ = other.previous_output_;
    script_ = other.script_;
    sequence_ = other.sequence_;
    return *this;
}

input& input::operator=(input&& other)
{
    previous_output_ = std::move(other.previous_output_);
    script_ = std::move(other.script_);
    sequence_ = other.sequence_;
    return *this;
}

bool input::operator==(const input& other) const
{
    return (sequence_ == other.sequence_)
        && (previous_output_ == other.previous_output_)
        && (script_ == other.script_);
}

bool input::operator!=(const input& other) const
{
    return !(*this == other);
}

// Deserialization.
//-----------------------------------------------------------------------------

input input::factory_from_data(const data_chunk& data, bool wire)
{
    input instance;
    instance.from_data(data, wire);
    return instance;
}

input input::factory_from_data(std::istream& stream, bool wire)
{
    input instance;
    instance.from_data(stream, wire);
    return instance;
}

input input::factory_from_data(reader& source, bool wire)
{
    input instance;
    instance.from_data(source, wire);
    return instance;
}

bool input::from_data(const data_chunk& data, bool wire)
{
    data_source istream(data);
    return from_data(istream, wire);
}

bool input::from_data(std::istream& stream, bool wire)
{
    istream_reader source(stream);
    return from_data(source, wire);
}

bool input::from_data(reader& source, bool)
{
    reset();

    if (!previous_output_.from_data(source))
        return false;

    script_.from_data(source, use_length_prefix);
    sequence_ = source.read_4_bytes_little_endian();

    if (!source)
        reset();

    return source;
}

void input::reset()
{
    previous_output_ = chain::output_point{};
    script_ = chain::script{};
    sequence_ = 0;
}

// Since empty script and zero sequence are valid this relies on the prevout.
bool input::is_valid() const
{
    return sequence_ != 0 || previous_output_.is_valid() || script_.is_valid();
}

// Serialization.
//-----------------------------------------------------------------------------

data_chunk input::to_data(bool wire) const
{
    data_chunk data;
    data_sink ostream(data);
    to_data(ostream, wire);
    ostream.flush();
    BITCOIN_ASSERT(data.size() == serialized_size(wire));
    return data;
}

void input::to_data(std::ostream& stream, bool wire) const
{
    ostream_writer sink(stream);
    to_data(sink, wire);
}

void input::to_data(writer& sink, bool) const
{
    previous_output_.to_data(sink);
    script_.to_data(sink, use_length_prefix);
    sink.write_4_bytes_little_endian(sequence_);
}

std::string input::to_string(uint32_t flags) const
{
    std::ostringstream text;

    text << previous_output_.to_string() << "\n"
        << "\t" << script_.to_string(flags) << "\n"
        << "\tsequence = " << sequence_ << "\n";

    return text.str();
}

// Size.
//-----------------------------------------------------------------------------

uint64_t input::serialized_size(bool) const
{
    return previous_output_.serialized_size() +
        script_.serialized_size(use_length_prefix) + sizeof(sequence_);
}

// Accessors.
//-----------------------------------------------------------------------------

output_point& input::previous_output()
{
    return previous_output_;
}

const output_point& input::previous_output() const
{
    return previous_output_;
}

void input::set_previous_output(const output_point& value)
{
    previous_output_ = value;
}

void input::set_previous_output(output_point&& value)
{
    previous_output_ = std::move(value);
}

chain::script& input::script()
{
    return script_;
}

const chain::script& input::script() const
{
    return script_;
}

void input::set_script(const chain::script& value)
{
    script_ = value;
}

void input::set_script(chain::script&& value)
{
    script_ = std::move(value);
}

uint32_t input::sequence() const
{
    return sequence_;
}

void input::set_sequence(uint32_t value)
{
    sequence_ = value;
}

// Validation helpers.
//-----------------------------------------------------------------------------

bool input::is_final() const
{
    return sequence_ == max_input_sequence;
}

size_t input::signature_operations(bool bip16_active) const
{
    auto sigops = script_.sigops(false);

    if (bip16_active)
    {
        // This cannot overflow because each total is limited by max ops.
        const auto& cache = previous_output_.validation.cache.script();
        sigops += script_.pay_script_hash_sigops(cache);
    }

    return sigops;
}

} // namespace chain
} // namespace libbitcoin
