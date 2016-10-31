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
#ifndef LIBBITCOIN_CHAIN_OUTPUT_HPP
#define LIBBITCOIN_CHAIN_OUTPUT_HPP

#include <cstddef>
#include <cstdint>
#include <istream>
#include <string>
#include <bitcoin/bitcoin/chain/script/script.hpp>
#include <bitcoin/bitcoin/define.hpp>
#include <bitcoin/bitcoin/utility/reader.hpp>
#include <bitcoin/bitcoin/utility/writer.hpp>

namespace libbitcoin {
namespace chain {

class BC_API output
{
public:
    typedef std::vector<output> list;

    /// This is a sentinel used in .value to indicate not found in store.
    /// This is a sentinel used in cache.value to indicate not populated.
    /// This is a consensus value used in script::generate_signature_hash.
    static const uint64_t not_found;

    // These properties facilitate block and transaction validation.
    // This validation data IS copied on output copy/move.
    struct validation
    {
        // This is a non-consensus sentinel used to indicate an output is unspent.
        static const uint32_t not_spent;

        // These are used by database only.
        size_t spender_height = validation::not_spent;
    };

    // Constructors.
    //-----------------------------------------------------------------------------

    output();

    output(output&& other);
    output(const output& other);

    output(uint64_t value, chain::script&& script);
    output(uint64_t value, const chain::script& script);

    // Operators.
    //-----------------------------------------------------------------------------

    /// This class is move assignable and copy assignable.
    output& operator=(output&& other);
    output& operator=(const output& other);

    bool operator==(const output& other) const;
    bool operator!=(const output& other) const;

    // Deserialization.
    //-----------------------------------------------------------------------------

    static output factory_from_data(const data_chunk& data, bool wire=true);
    static output factory_from_data(std::istream& stream, bool wire=true);
    static output factory_from_data(reader& source, bool wire=true);

    bool from_data(const data_chunk& data, bool wire=true);
    bool from_data(std::istream& stream, bool wire=true);
    bool from_data(reader& source, bool wire=true);

    bool is_valid() const;

    // Serialization.
    //-----------------------------------------------------------------------------

    data_chunk to_data(bool wire=true) const;
    void to_data(std::ostream& stream, bool wire=true) const;
    void to_data(writer& sink, bool wire=true) const;

    std::string to_string(uint32_t flags) const;

    // Properties (size, accessors, cache).
    //-----------------------------------------------------------------------------

    uint64_t serialized_size(bool wire=true) const;

    uint64_t value() const;
    void set_value(uint64_t value);

    // Deprecated (unsafe).
    chain::script& script();

    const chain::script& script() const;
    void set_script(const chain::script& value);
    void set_script(chain::script&& value);

    // Validation.
    //-----------------------------------------------------------------------------

    size_t signature_operations() const;

    // These fields do not participate in wire serialization or comparison.
    mutable validation validation;

protected:
    output(uint64_t value, chain::script&& script, size_t spender_height);
    output(uint64_t value, const chain::script& script, size_t spender_height);

    void reset();

private:
    uint64_t value_;
    chain::script script_;
};

} // namespace chain
} // namespace libbitcoin

#endif
