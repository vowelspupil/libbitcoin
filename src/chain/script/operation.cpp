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

// This is policy, not consensus.
const size_t operation::max_null_data_size = 80;

// Constructors.
//-----------------------------------------------------------------------------

operation::operation()
  : code_(opcode::bad_operation)
{
}

operation::operation(operation&& other)
  : operation(other.code_, std::move(other.data_))
{
}

operation::operation(const operation& other)
  : operation(other.code_, other.data_)
{
}

operation::operation(opcode code, data_chunk&& data)
  : code_(code), data_(std::move(data))
{
}

operation::operation(opcode code, const data_chunk& data)
  : code_(code), data_(data)
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

// BUGBUG: bad_operation is a valid parse.
bool operation::is_valid() const
{
    return (code_ != opcode::bad_operation) || !data_.empty();
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

    // The value must be a valid opcode on the wire.
    if (!operation::is_wire(code_))
        source.invalidate();

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

// protected
void operation::reset()
{
    code_ = opcode::bad_operation;
    data_.clear();
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
    const auto code = opcode_to_byte(*this);

    switch (code_)
    {
        case opcode::special:
            // For 0 through 75 the wire opcode is also the data size.
            sink.write_byte(code);
            sink.write_bytes(data_);
            break;
        case opcode::pushdata1:
            sink.write_byte(code);
            sink.write_byte(safe_unsigned<uint8_t>(size));
            sink.write_bytes(data_);
            break;
        case opcode::pushdata2:
            sink.write_byte(code);
            sink.write_2_bytes_little_endian(safe_unsigned<uint16_t>(size));
            sink.write_bytes(data_);
            break;
        case opcode::pushdata4:
            sink.write_byte(code);
            sink.write_4_bytes_little_endian(safe_unsigned<uint32_t>(size));
            sink.write_bytes(data_);
            break;
        case opcode::raw_data:
            sink.write_bytes(data_);
            break;
        default:
            sink.write_byte(code);
            break;
    }
}

std::string operation::to_string(uint32_t flags) const
{
    std::ostringstream ss;

    if (data_.empty())
        ss << opcode_to_string(code_, flags);
    else
        ss << "[ " << encode_base16(data_) << " ]";

    return ss.str();
}

// Properties (size, accessors, cache).
//-----------------------------------------------------------------------------

uint64_t operation::serialized_size() const
{
    switch (code_)
    {
        case opcode::special:
            return sizeof(uint8_t) + data_.size();
        case opcode::pushdata1:
            return sizeof(uint8_t) + sizeof(uint8_t) + data_.size();
        case opcode::pushdata2:
            return sizeof(uint8_t) + sizeof(uint16_t) + data_.size();
        case opcode::pushdata4:
            return sizeof(uint8_t) + sizeof(uint32_t) + data_.size();
        case opcode::raw_data:
            return data_.size();
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

// deprecated (unsafe)
data_chunk& operation::data()
{
    return data_;
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
    static constexpr auto pushdata1 = static_cast<uint8_t>(opcode::pushdata1);

    switch (static_cast<opcode>(byte))
    {
        case opcode::pushdata1:
            return source.read_byte();
        case opcode::pushdata2:
            return source.read_2_bytes_little_endian();
        case opcode::pushdata4:
            return source.read_4_bytes_little_endian();
        default:
            // For 0 through 75 the wire opcode is also the data size.
            return byte < pushdata1 ? byte : 0;
    }
}

bool operation::is_disabled(const operation& op)
{
    return is_disabled(op.code());
}

bool operation::is_oversized(const operation& op)
{
    return op.data().size() > max_data_script_size;
}

opcode operation::opcode_from_size(size_t size)
{
    static constexpr auto pushdata1 = static_cast<uint8_t>(opcode::pushdata1);

    // For 0 through 75 the wire opcode is also the data size.
    if (size < pushdata1)
        return opcode::special;

    if (size <= max_uint8)
        return opcode::pushdata1;

    if (size <= max_uint16)
        return opcode::pushdata2;

    if (size <= max_uint32)
        return opcode::pushdata4;

    return opcode::bad_operation;
}

uint8_t operation::opcode_to_byte(const operation& op)
{
    // For 0 through 75 the wire opcode is also the data size.
    return (op.code_ == opcode::special) ?
        safe_unsigned<uint8_t>(op.data_.size()) :
        static_cast<uint8_t>(op.code_);
}

// Determine if code pushes data onto the stack.
bool operation::is_push(opcode code)
{
    switch (code)
    {
        case opcode::zero:
        case opcode::special:
        case opcode::pushdata1:
        case opcode::pushdata2:
        case opcode::pushdata4:
        case opcode::negative_1:
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
        case opcode::positive_1:
        case opcode::positive_2:
        case opcode::positive_3:
        case opcode::positive_4:
        case opcode::positive_5:
        case opcode::positive_6:
        case opcode::positive_7:
        case opcode::positive_8:
        case opcode::positive_9:
        case opcode::positive_10:
        case opcode::positive_11:
        case opcode::positive_12:
        case opcode::positive_13:
        case opcode::positive_14:
        case opcode::positive_15:
        case opcode::positive_16:
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
        case opcode::disabled_2mul:
        case opcode::disabled_2div:
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

// These codes are parsed and, except for op_reserved, contribute to op count.
// If they are encountered in execution they cause failure.
// Due to conditional execution it is possible for them to be skipped.
bool operation::is_reserved(opcode code)
{
    switch (code)
    {
        case opcode::reserved:
        case opcode::reserved_ver:
        case opcode::reserved_verif:
        case opcode::reserved_vernotif:
        case opcode::reserved1:
        case opcode::reserved2:
            return true;

        default:
            return false;
    }
}

// Wire codes are those that deserialize.
// Wire opcodes include disabled/reserved, which parse but fail run if hit.
// Wire opcodes include specials, which map into opcode::special for execution.
bool operation::is_wire(opcode code)
{
    static constexpr auto low = static_cast<uint8_t>(opcode::zero);
    static constexpr auto high = static_cast<uint8_t>(opcode::nop10);

    const auto value = static_cast<uint8_t>(code);
    return value >= low && value <= high;
}

// Wire special codes are those that are mapped to the "special" operator.
bool operation::is_wire_special(opcode code)
{
    static constexpr auto below = static_cast<uint8_t>(opcode::zero);
    static constexpr auto above = static_cast<uint8_t>(opcode::pushdata1);

    const auto value = static_cast<uint8_t>(code);
    return value > below && value < above;
}

bool operation::is_push_only(const operation::stack& ops)
{
    const auto push = [](const operation& op)
    {
        return is_push(op.code());
    };

    return std::all_of(ops.begin(), ops.end(), push);
}

// Return the op_positive_# index (i.e. value of #).
uint8_t operation::opcode_to_positive(opcode code)
{
    BITCOIN_ASSERT(is_positive(code));
    static constexpr auto op_0 = static_cast<uint8_t>(opcode::positive_1) - 1;
    return static_cast<uint8_t>(code) - op_0;
}

// Utilities: pattern comparisons.
// ----------------------------------------------------------------------------

bool operation::is_null_data_pattern(const operation::stack& ops)
{
    return ops.size() == 2
        && ops[0].code() == opcode::return_
        && ops[1].code() == opcode::special
        && ops[1].data().size() <= max_null_data_size;
}

bool operation::is_pay_multisig_pattern(const operation::stack& ops)
{
    static constexpr size_t op_1 = static_cast<uint8_t>(opcode::positive_1);
    static constexpr size_t op_16 = static_cast<uint8_t>(opcode::positive_16);

    const auto op_count = ops.size();

    if (op_count < 4 || ops[op_count - 1].code() != opcode::checkmultisig)
        return false;

    const auto op_m = static_cast<uint8_t>(ops[0].code());
    const auto op_n = static_cast<uint8_t>(ops[op_count - 2].code());

    if (op_m < op_1 || op_m > op_n || op_n < op_1 || op_n > op_16)
        return false;

    const auto n = op_n - op_1;
    const auto points = op_count - 3u;

    if (n != points)
        return false;

    for (auto op = ops.begin() + 1; op != ops.end() - 2; ++op)
        if (!is_public_key(op->data()))
            return false;

    return true;
}

bool operation::is_pay_public_key_pattern(const operation::stack& ops)
{
    return ops.size() == 2
        && ops[0].code() == opcode::special
        && is_public_key(ops[0].data())
        && ops[1].code() == opcode::checksig;
}

bool operation::is_pay_key_hash_pattern(const operation::stack& ops)
{
    return ops.size() == 5
        && ops[0].code() == opcode::dup
        && ops[1].code() == opcode::hash160
        && ops[2].code() == opcode::special
        && ops[2].data().size() == short_hash_size
        && ops[3].code() == opcode::equalverify
        && ops[4].code() == opcode::checksig;
}

bool operation::is_pay_script_hash_pattern(const operation::stack& ops)
{
    return ops.size() == 3
        && ops[0].code() == opcode::hash160
        && ops[1].code() == opcode::special
        && ops[1].data().size() == short_hash_size
        && ops[2].code() == opcode::equal;
}

bool operation::is_sign_multisig_pattern(const operation::stack& ops)
{
    if (ops.size() < 2 || !is_push_only(ops))
        return false;

    if (ops.front().code() != opcode::zero)
        return false;

    return true;
}

bool operation::is_sign_public_key_pattern(const operation::stack& ops)
{
    return ops.size() == 1 && is_push_only(ops);
}

bool operation::is_sign_key_hash_pattern(const operation::stack& ops)
{
    return ops.size() == 2 && is_push_only(ops) &&
        is_public_key(ops.back().data());
}

bool operation::is_sign_script_hash_pattern(const operation::stack& ops)
{
    if (ops.size() < 2 || !is_push_only(ops))
        return false;

    const auto& redeem_data = ops.back().data();

    if (redeem_data.empty())
        return false;

    script redeem;

    if (!redeem.from_data(redeem_data, false, script::parse_mode::strict))
        return false;

    // Is the redeem script a standard pay (output) script?
    const auto redeem_script_pattern = redeem.pattern();
    return redeem_script_pattern == script_pattern::pay_multisig
        || redeem_script_pattern == script_pattern::pay_public_key
        || redeem_script_pattern == script_pattern::pay_key_hash
        || redeem_script_pattern == script_pattern::pay_script_hash
        || redeem_script_pattern == script_pattern::null_data;
}

// Utilities: pattern templates.
// ----------------------------------------------------------------------------

operation::stack operation::to_null_data_pattern(data_slice data)
{
    if (data.size() > max_null_data_size)
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
    static constexpr size_t op_1 = static_cast<uint8_t>(opcode::positive_1);
    static constexpr size_t op_16 = static_cast<uint8_t>(opcode::positive_16);
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

} // namespace chain
} // namespace libbitcoin
