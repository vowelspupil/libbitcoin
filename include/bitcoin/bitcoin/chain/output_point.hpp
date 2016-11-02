/**
 * Copyright (c) 2011-2016 libbitcoin developers (see AUTHORS)
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
#ifndef LIBBITCOIN_CHAIN_OUTPUT_POINT_HPP
#define LIBBITCOIN_CHAIN_OUTPUT_POINT_HPP

#include <cstddef>
#include <cstdint>
#include <vector>
#include <bitcoin/bitcoin/chain/output.hpp>
#include <bitcoin/bitcoin/chain/point.hpp>
#include <bitcoin/bitcoin/chain/script/script.hpp>
#include <bitcoin/bitcoin/define.hpp>

namespace libbitcoin {
namespace chain {

class BC_API output_point
  : public point
{
public:

    // This validation data IS copied on output_point copy/move.
    // These properties facilitate block and transaction validation.
    struct validation
    {
        /// This is a .height sentinel.
        static const size_t not_specified;

        /// An output is spent if a valid transaction has a valid claim on it.
        /// When validating blocks only long chain blocks can have a claim.
        /// When validating memory pool tx another mempool tx can have a claim.
        bool spent = false;

        /// A spend is confirmed if spender is in long chain (not memory pool).
        bool confirmed = false;

        /// Coinbase prevout height is necessary in determining maturity.
        /// If this is set to not_specified the input is considered mature.
        /// This must be set to not_specified if the input is coinbase.
        /// This must be set to not_specified if the output is non-coinbase.
        /// This may be set to not_specified if the prevout is spent.
        size_t height = validation::not_specified;

        /// The output cache contains the output referenced by the input point.
        /// If the cache.value is not_found then the output has not been found.
        output cache = output{ output::not_found, script{} };
    };

    // Constructors.
    //-----------------------------------------------------------------------------

    output_point();

    output_point(point&& other);
    output_point(const point& value);

    output_point(output_point&& other);
    output_point(const output_point& other);

    output_point(hash_digest&& hash, uint32_t index);
    output_point(const hash_digest& hash, uint32_t index);

    // Operators.
    //-----------------------------------------------------------------------------
    // This class is move assignable and copy assignable.

    output_point& operator=(point&& other);
    output_point& operator=(const point&);
    output_point& operator=(output_point&& other);
    output_point& operator=(const output_point&);

    bool operator==(const point& other) const;
    bool operator!=(const point& other) const;
    bool operator==(const output_point& other) const;
    bool operator!=(const output_point& other) const;

    // Deserialization.
    //-----------------------------------------------------------------------------

    static output_point factory_from_data(const data_chunk& data);
    static output_point factory_from_data(std::istream& stream);
    static output_point factory_from_data(reader& source);

    // Validation.
    //-----------------------------------------------------------------------------

    /// False if previous output is not cached.
    /// True if the previous output is mature enough to spend from target.
    bool is_mature(size_t target_height) const;

    // These fields do not participate in serialization or comparison.
    mutable validation validation;

protected:
    // So that input may call reset from its own.
    friend class input;
};

struct BC_API points_info
{
    output_point::list points;
    uint64_t change;
};

struct BC_API output_info
{
    typedef std::vector<output_info> list;

    output_point point;
    uint64_t value;
};

} // namespace chain
} // namespace libbitcoin

#endif
