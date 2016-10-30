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
#include <bitcoin/bitcoin/chain/header.hpp>

#include <cstddef>
#include <chrono>
#include <utility>
#include <bitcoin/bitcoin/chain/chain_state.hpp>
#include <bitcoin/bitcoin/constants.hpp>
#include <bitcoin/bitcoin/error.hpp>
#include <bitcoin/bitcoin/math/hash_number.hpp>
#include <bitcoin/bitcoin/utility/container_sink.hpp>
#include <bitcoin/bitcoin/utility/container_source.hpp>
#include <bitcoin/bitcoin/utility/istream_reader.hpp>
#include <bitcoin/bitcoin/utility/ostream_writer.hpp>

namespace libbitcoin {
namespace chain {

const size_t header::validation::orphan_height = 0;

// Constructors.
//-----------------------------------------------------------------------------

header::header()
  : header(0, null_hash, null_hash, 0, 0, 0)
{
}

header::header(header&& other)
  : header(other.version_, std::move(other.previous_block_hash_),
      std::move(other.merkle_), other.timestamp_, other.bits_, other.nonce_)
{
}

header::header(const header& other)
  : header(other.version_, other.previous_block_hash_, other.merkle_,
        other.timestamp_, other.bits_, other.nonce_)
{
}

header::header(header&& other, hash_digest&& hash)
  : header(other.version_, std::move(other.previous_block_hash_),
      std::move(other.merkle_), other.timestamp_, other.bits_, other.nonce_)
{
    hash_ = std::make_shared<hash_digest>(std::move(hash));
}

header::header(const header& other, const hash_digest& hash)
  : header(other.version_, other.previous_block_hash_, other.merkle_,
        other.timestamp_, other.bits_, other.nonce_)
{
    hash_ = std::make_shared<hash_digest>(hash);
}

header::header(uint32_t version, hash_digest&& previous_block_hash,
    hash_digest&& merkle, uint32_t timestamp, uint32_t bits, uint32_t nonce)
  : version_(version), previous_block_hash_(std::move(previous_block_hash)),
    merkle_(std::move(merkle)), timestamp_(timestamp), bits_(bits),
    nonce_(nonce)
{
}

header::header(uint32_t version, const hash_digest& previous_block_hash,
    const hash_digest& merkle, uint32_t timestamp, uint32_t bits,
    uint32_t nonce)
  : version_(version), previous_block_hash_(previous_block_hash),
    merkle_(merkle), timestamp_(timestamp), bits_(bits), nonce_(nonce)
{
}

// Operators.
//-----------------------------------------------------------------------------

header& header::operator=(header&& other)
{
    version_ = other.version_;
    previous_block_hash_ = std::move(other.previous_block_hash_);
    merkle_ = std::move(other.merkle_);
    timestamp_ = other.timestamp_;
    bits_ = other.bits_;
    nonce_ = other.nonce_;
    return *this;
}

// TODO: eliminate header copies and then delete this.
header& header::operator=(const header& other)
{
    version_ = other.version_;
    previous_block_hash_ = other.previous_block_hash_;
    merkle_ = other.merkle_;
    timestamp_ = other.timestamp_;
    bits_ = other.bits_;
    nonce_ = other.nonce_;
    return *this;
}

bool header::operator==(const header& other) const
{
    return (version_ == other.version_)
        && (previous_block_hash_ == other.previous_block_hash_)
        && (merkle_ == other.merkle_)
        && (timestamp_ == other.timestamp_)
        && (bits_ == other.bits_)
        && (nonce_ == other.nonce_);
}

bool header::operator!=(const header& other) const
{
    return !(*this == other);
}

// Deserialization.
//-----------------------------------------------------------------------------

// static
header header::factory_from_data(const data_chunk& data)
{
    header instance;
    instance.from_data(data);
    return instance;
}

// static
header header::factory_from_data(std::istream& stream)
{
    header instance;
    instance.from_data(stream);
    return instance;
}

// static
header header::factory_from_data(reader& source)
{
    header instance;
    instance.from_data(source);
    return instance;
}

bool header::from_data(const data_chunk& data)
{
    data_source istream(data);
    return from_data(istream);
}

bool header::from_data(std::istream& stream)
{
    istream_reader source(stream);
    return from_data(source);
}

bool header::from_data(reader& source)
{
    reset();

    version_ = source.read_4_bytes_little_endian();
    previous_block_hash_ = source.read_hash();
    merkle_ = source.read_hash();
    timestamp_ = source.read_4_bytes_little_endian();
    bits_ = source.read_4_bytes_little_endian();
    nonce_ = source.read_4_bytes_little_endian();

    if (!source)
        reset();

    return source;
}

// protected
void header::reset()
{
    version_ = 0;
    previous_block_hash_.fill(0);
    merkle_.fill(0);
    timestamp_ = 0;
    bits_ = 0;
    nonce_ = 0;
    invalidate_cache();
}

bool header::is_valid() const
{
    return (version_ != 0) ||
        (previous_block_hash_ != null_hash) ||
        (merkle_ != null_hash) ||
        (timestamp_ != 0) ||
        (bits_ != 0) ||
        (nonce_ != 0);
}

// Serialization.
//-----------------------------------------------------------------------------

data_chunk header::to_data() const
{
    data_chunk data;
    data.reserve(serialized_size());
    data_sink ostream(data);
    to_data(ostream);
    ostream.flush();
    BITCOIN_ASSERT(data.size() == serialized_size());
    return data;
}

void header::to_data(std::ostream& stream) const
{
    ostream_writer sink(stream);
    to_data(sink);
}

void header::to_data(writer& sink) const
{
    sink.write_4_bytes_little_endian(version_);
    sink.write_hash(previous_block_hash_);
    sink.write_hash(merkle_);
    sink.write_4_bytes_little_endian(timestamp_);
    sink.write_4_bytes_little_endian(bits_);
    sink.write_4_bytes_little_endian(nonce_);
}

// Size.
//-----------------------------------------------------------------------------

// static
uint64_t header::satoshi_fixed_size()
{
    return sizeof(version_)
        + hash_size
        + hash_size
        + sizeof(timestamp_)
        + sizeof(bits_)
        + sizeof(nonce_);
}

uint64_t header::serialized_size() const
{
    return satoshi_fixed_size();
}

// Accessors.
//-----------------------------------------------------------------------------

uint32_t header::version() const
{
    return version_;
}

void header::set_version(uint32_t value)
{
    version_ = value;
    invalidate_cache();
}

hash_digest& header::previous_block_hash()
{
    return previous_block_hash_;
}

const hash_digest& header::previous_block_hash() const
{
    return previous_block_hash_;
}

void header::set_previous_block_hash(const hash_digest& value)
{
    previous_block_hash_ = value;
    invalidate_cache();
}

void header::set_previous_block_hash(hash_digest&& value)
{
    previous_block_hash_ = std::move(value);
    invalidate_cache();
}

hash_digest& header::merkle()
{
    return merkle_;
}

const hash_digest& header::merkle() const
{
    return merkle_;
}

void header::set_merkle(const hash_digest& value)
{
    merkle_ = value;
    invalidate_cache();
}

void header::set_merkle(hash_digest&& value)
{
    merkle_ = std::move(value);
    invalidate_cache();
}

uint32_t header::timestamp() const
{
    return timestamp_;
}

void header::set_timestamp(uint32_t value)
{
    timestamp_ = value;
    invalidate_cache();
}

uint32_t header::bits() const
{
    return bits_;
}

void header::set_bits(uint32_t value)
{
    bits_ = value;
    invalidate_cache();
}

uint32_t header::nonce() const
{
    return nonce_;
}

void header::set_nonce(uint32_t value)
{
    nonce_ = value;
    invalidate_cache();
}

// Cache.
//-----------------------------------------------------------------------------

// protected
void header::invalidate_cache() const
{
    ///////////////////////////////////////////////////////////////////////////
    // Critical Section
    mutex_.lock_upgrade();

    if (hash_)
    {
        mutex_.unlock_upgrade_and_lock();
        //+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
        hash_.reset();
        //---------------------------------------------------------------------
        mutex_.unlock_and_lock_upgrade();
    }

    mutex_.unlock_upgrade();
    ///////////////////////////////////////////////////////////////////////////
}

hash_digest header::hash() const
{
    ///////////////////////////////////////////////////////////////////////////
    // Critical Section
    mutex_.lock_upgrade();

    if (!hash_)
    {
        //+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
        mutex_.unlock_upgrade_and_lock();
        hash_ = std::make_shared<hash_digest>(bitcoin_hash(to_data()));
        mutex_.unlock_and_lock_upgrade();
        //---------------------------------------------------------------------
    }

    const auto hash = *hash_;
    mutex_.unlock_upgrade();
    ///////////////////////////////////////////////////////////////////////////

    return hash;
}

// Validation helpers.
//-----------------------------------------------------------------------------

bool header::is_valid_time_stamp() const
{
    // Use system clock because we require accurate time of day.
    typedef std::chrono::system_clock wall_clock;
    static const auto two_hours = std::chrono::hours(time_stamp_future_hours);
    const auto time = wall_clock::from_time_t(timestamp_);
    const auto future = wall_clock::now() + two_hours;
    return time <= future;
}

bool header::is_valid_proof_of_work() const
{
    // TODO: This should be statically-initialized (optimization).
    hash_number maximum;
    if (!maximum.set_compact(max_work_bits))
        return false;

    hash_number target;
    if (!target.set_compact(bits_) || target > maximum)
        return false;

    hash_number value(hash());
    return value <= target;
}

// Validation.
//-----------------------------------------------------------------------------

code header::check() const
{
    if (!is_valid_proof_of_work())
        return error::invalid_proof_of_work;

    else if (!is_valid_time_stamp())
        return error::futuristic_timestamp;

    else
        return error::success;
}

code header::accept(const chain_state& state) const
{
    if (state.is_checkpoint_failure(hash()))
        return error::checkpoints_failed;

    else if (version_ < state.minimum_version())
        return error::old_version_block;

    else if (bits_ != state.work_required())
        return error::incorrect_proof_of_work;

    else if (timestamp_ <= state.median_time_past())
        return error::timestamp_too_early;

    else
        return error::success;
}

} // namespace chain
} // namespace libbitcoin
