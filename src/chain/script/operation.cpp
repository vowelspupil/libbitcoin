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
#include <bitcoin/bitcoin/chain/script/operation.hpp>

#include <algorithm>
#include <sstream>
#include <bitcoin/bitcoin/chain/script/rule_fork.hpp>
#include <bitcoin/bitcoin/chain/script/opcode.hpp>
#include <bitcoin/bitcoin/chain/script/script.hpp>
#include <bitcoin/bitcoin/chain/script/script_pattern.hpp>
#include <bitcoin/bitcoin/constants.hpp>
#include <bitcoin/bitcoin/formats/base_16.hpp>
#include <bitcoin/bitcoin/math/elliptic_curve.hpp>
#include <bitcoin/bitcoin/utility/container_sink.hpp>
#include <bitcoin/bitcoin/utility/container_source.hpp>
#include <bitcoin/bitcoin/utility/istream_reader.hpp>
#include <bitcoin/bitcoin/utility/ostream_writer.hpp>

namespace libbitcoin {
namespace chain {

// Constructors.
//-----------------------------------------------------------------------------

operation::operation()
  : code_(opcode::push_size_0), valid_(false)
{
}

operation::operation(operation&& other)
  : operation(other.code_, std::move(other.data_), other.valid_)
{
}

operation::operation(const operation& other)
  : operation(other.code_, other.data_, other.valid_)
{
}

// TODO: compute minimal code and set valid.
operation::operation(data_chunk&& data)
  : code_(opcode::push_size_0), data_(std::move(data)), valid_(true)
{
}

// TODO: compute minimal code and set valid.
operation::operation(const data_chunk& data)
  : code_(opcode::push_size_0), data_(data), valid_(true)
{
}

// protected
operation::operation(opcode code, data_chunk&& data, bool valid)
  : code_(code), data_(std::move(data)), valid_(valid)
{
}

// protected
operation::operation(opcode code, const data_chunk& data, bool valid)
  : code_(code), data_(data), valid_(valid)
{
}

// Operators.
//-----------------------------------------------------------------------------

operation& operation::operator=(operation&& other)
{
    code_ = other.code_;
    data_ = std::move(other.data_);
    return *this;
}

operation& operation::operator=(const operation& other)
{
    code_ = other.code_;
    data_ = other.data_;
    return *this;
}

bool operation::operator==(const operation& other) const
{
    return (code_ == other.code_) && (data_ == other.data_);
}

bool operation::operator!=(const operation& other) const
{
    return !(*this == other);
}

// Deserialization.
//-----------------------------------------------------------------------------

// static
operation operation::factory_from_data(const data_chunk& data)
{
    operation instance;
    instance.from_data(data);
    return instance;
}

// static
operation operation::factory_from_data(std::istream& stream)
{
    operation instance;
    instance.from_data(stream);
    return instance;
}

// static
operation operation::factory_from_data(reader& source)
{
    operation instance;
    instance.from_data(source);
    return instance;
}

bool operation::is_valid() const
{
    return valid_ || code_ != opcode::push_size_0 || !data_.empty();
}

bool operation::from_data(const data_chunk& data)
{
    data_source istream(data);
    return from_data(istream);
}

bool operation::from_data(std::istream& stream)
{
    istream_reader source(stream);
    return from_data(source);
}

// This rejects invalid operations (always strict).
bool operation::from_data(reader& source)
{
    reset();

    const auto byte = source.read_byte();
    const auto size = read_data_size(byte, source);
    static_assert(sizeof(size) == sizeof(uint32_t), "unexpected size");
    code_ = static_cast<opcode>(byte);

    if (size != 0)
    {
        // This cannot fail because size is uint32_t.
        code_ = opcode_from_size(size);
        data_ = source.read_bytes(size);
    }

    if (!source)
        reset();

    return source;
}

bool operation::from_string(const std::string& token)
{
    reset();
    valid_ = true;

    if (!opcode_from_string(code_, token))
        reset();

    return valid_;
}

// protected
void operation::reset()
{
    code_ = opcode::push_size_0;
    data_.clear();
    valid_ = false;
}

// Serialization.
//-----------------------------------------------------------------------------

data_chunk operation::to_data() const
{
    data_chunk data;
    data_sink ostream(data);
    to_data(ostream);
    ostream.flush();
    BITCOIN_ASSERT(data.size() == serialized_size());
    return data;
}

void operation::to_data(std::ostream& stream) const
{
    ostream_writer sink(stream);
    to_data(sink);
}

void operation::to_data(writer& sink) const
{
    const auto size = data_.size();
    const auto code = opcode_byte();

    switch (code_)
    {
        case opcode::special:
            // For 0 through 75 the wire opcode is also the data size.
            sink.write_byte(code);
            sink.write_bytes(data_);
            break;
        case opcode::push_size_1:
            sink.write_byte(code);
            sink.write_byte(safe_unsigned<uint8_t>(size));
            sink.write_bytes(data_);
            break;
        case opcode::push_size_2:
            sink.write_byte(code);
            sink.write_2_bytes_little_endian(safe_unsigned<uint16_t>(size));
            sink.write_bytes(data_);
            break;
        case opcode::push_size_4:
            sink.write_byte(code);
            sink.write_4_bytes_little_endian(safe_unsigned<uint32_t>(size));
            sink.write_bytes(data_);
            break;
        default:
            sink.write_byte(code);
            break;
    }
}

std::string operation::to_string(uint32_t active_forks) const
{
    std::ostringstream text;

    if (data_.empty())
        text << opcode_to_string(code_, active_forks);
    else
        text << "[ " << encode_base16(data_) << " ]";

    return text.str();
}

// Properties (size, accessors, cache).
//-----------------------------------------------------------------------------

uint64_t operation::serialized_size() const
{
    switch (code_)
    {
        case opcode::special:
            return sizeof(uint8_t) + data_.size();
        case opcode::push_size_1:
            return sizeof(uint8_t) + sizeof(uint8_t) + data_.size();
        case opcode::push_size_2:
            return sizeof(uint8_t) + sizeof(uint16_t) + data_.size();
        case opcode::push_size_4:
            return sizeof(uint8_t) + sizeof(uint32_t) + data_.size();
        default:
            return sizeof(uint8_t);
    }
}

opcode operation::code() const
{
    return code_;
}

void operation::set_code(opcode code)
{
    code_ = code;
}

const data_chunk& operation::data() const
{
    return data_;
}

void operation::set_data(data_chunk&& data)
{
    data_ = std::move(data);
}

void operation::set_data(const data_chunk& data)
{
    data_ = data;
}

// Utilities.
//-------------------------------------------------------------------------
// static

// private
uint32_t operation::read_data_size(uint8_t byte, reader& source)
{
    static constexpr auto pushdata1 = static_cast<uint8_t>(opcode::push_size_1);

    switch (static_cast<opcode>(byte))
    {
        case opcode::push_size_1:
            return source.read_byte();
        case opcode::push_size_2:
            return source.read_2_bytes_little_endian();
        case opcode::push_size_4:
            return source.read_4_bytes_little_endian();
        default:
            // For 0 through 75 the wire opcode is also the data size.
            return byte < pushdata1 ? byte : 0;
    }
}

opcode operation::opcode_from_size(size_t size)
{
    static constexpr auto pushdata1 = static_cast<uint8_t>(opcode::push_size_1);

    // For 0 through 75 the wire opcode is also the data size.
    if (size < pushdata1)
        return opcode::special;

    if (size <= max_uint8)
        return opcode::push_size_1;

    if (size <= max_uint16)
        return opcode::push_size_2;

    if (size <= max_uint32)
        return opcode::push_size_4;

    return opcode::bad_operation;
}

// Determine if code pushes data onto the stack.
bool operation::is_push(opcode code)
{
    switch (code)
    {
        case opcode::push_size_0:
        case opcode::push_size_1:
        case opcode::push_size_2:
        case opcode::push_size_4:
        case opcode::push_negative_1:
            return true;

        default:
            return is_positive(code);
    }
}

// Operation counter increments for all codes above op_positive_16.
bool operation::is_counted(opcode code)
{
    static constexpr auto low = static_cast<uint8_t>(opcode::nop);
    static constexpr auto high = static_cast<uint8_t>(opcode::nop10);

    const auto value = static_cast<uint8_t>(code);
    return value >= low && value <= high;
}

// Determine if code pushes a positive number [1..16] onto the stack.
bool operation::is_positive(opcode code)
{
    switch (code)
    {
        case opcode::push_positive_1:
        case opcode::push_positive_2:
        case opcode::push_positive_3:
        case opcode::push_positive_4:
        case opcode::push_positive_5:
        case opcode::push_positive_6:
        case opcode::push_positive_7:
        case opcode::push_positive_8:
        case opcode::push_positive_9:
        case opcode::push_positive_10:
        case opcode::push_positive_11:
        case opcode::push_positive_12:
        case opcode::push_positive_13:
        case opcode::push_positive_14:
        case opcode::push_positive_15:
        case opcode::push_positive_16:
            return true;

        default:
            return false;
    }
}

// Determine if code is a conditional operator.
bool operation::is_conditional(opcode code)
{
    switch (code)
    {
        case opcode::if_:
        case opcode::notif:
        case opcode::else_:
        case opcode::endif:
            return true;

        default:
            return false;
    }
}

// These codes are parsed and contribute to op count.
// If they are encountered in execution they cause failure.
// These can not be skipped due to conditional execution so they always fail.
bool operation::is_disabled(opcode code)
{
    switch (code)
    {
        case opcode::disabled_cat:
        case opcode::disabled_substr:
        case opcode::disabled_left:
        case opcode::disabled_right:
        case opcode::disabled_invert:
        case opcode::disabled_and:
        case opcode::disabled_or:
        case opcode::disabled_xor:
        case opcode::disabled_mul2:
        case opcode::disabled_div2:
        case opcode::disabled_mul:
        case opcode::disabled_div:
        case opcode::disabled_mod:
        case opcode::disabled_lshift:
        case opcode::disabled_rshift:
            return true;

        default:
            return false;
    }
}

// Return the op_positive_# index (i.e. value of #).
uint8_t operation::opcode_to_positive(opcode code)
{
    BITCOIN_ASSERT(is_positive(code));
    static constexpr auto op_0 = static_cast<uint8_t>(opcode::push_positive_1) - 1;
    return static_cast<uint8_t>(code) - op_0;
}

// Utilities: pattern templates.
// ----------------------------------------------------------------------------

operation::stack operation::to_null_data_pattern(data_slice data)
{
    if (data.size() > script::max_null_data_size)
        return{};

    return operation::stack
    {
        { opcode::return_, {} },
        { opcode::special, to_chunk(data) }
    };
}

operation::stack operation::to_pay_public_key_pattern(data_slice point)
{
    if (!is_public_key(point))
        return{};

    return operation::stack
    {
        { opcode::special, to_chunk(point) },
        { opcode::checksig, {} }
    };
}

operation::stack operation::to_pay_multisig_pattern(uint8_t signatures,
    const point_list& points)
{
    const auto conversion = [](const ec_compressed& point)
    {
        return to_chunk(point);
    };

    data_stack chunks(points.size());
    std::transform(points.begin(), points.end(), chunks.begin(), conversion);
    return to_pay_multisig_pattern(signatures, chunks);
}

operation::stack operation::to_pay_multisig_pattern(uint8_t signatures,
    const data_stack& points)
{
    static constexpr size_t op_1 = static_cast<uint8_t>(opcode::push_positive_1);
    static constexpr size_t op_16 = static_cast<uint8_t>(opcode::push_positive_16);
    static constexpr size_t zero = op_1 - 1;
    static constexpr size_t max = op_16 - zero;

    const auto m = signatures;
    const auto n = points.size();

    if (m < 1 || m > n || n < 1 || n > max)
        return operation::stack();

    const auto op_m = static_cast<opcode>(m + zero);
    const auto op_n = static_cast<opcode>(points.size() + zero);

    operation::stack ops(points.size() + 3);
    ops.push_back({ op_m, {} });

    for (const auto point: points)
    {
        if (!is_public_key(point))
            return{};

        ops.emplace_back(opcode::special, point);
    }

    ops.push_back({ op_n, {} });
    ops.push_back({ opcode::checkmultisig, {} });
    return ops;
}

operation::stack operation::to_pay_key_hash_pattern(const short_hash& hash)
{
    return operation::stack
    {
        { opcode::dup, {} },
        { opcode::hash160, {} },
        { opcode::special, to_chunk(hash) },
        { opcode::equalverify, {} },
        { opcode::checksig, {} }
    };
}

operation::stack operation::to_pay_script_hash_pattern(const short_hash& hash)
{
    return operation::stack
    {
        { opcode::hash160, {} },
        { opcode::special, to_chunk(hash) },
        { opcode::equal, {} }
    };
}

// Validation.
//-------------------------------------------------------------------------

bool operation::is_disabled() const
{
    return is_disabled(code_);
}

bool operation::is_oversized() const
{
    return data_.size() > max_data_script_size;
}

uint8_t operation::opcode_byte() const
{
    // The code has already been computed.
    return static_cast<uint8_t>(code_);
}

} // namespace chain
} // namespace libbitcoin
