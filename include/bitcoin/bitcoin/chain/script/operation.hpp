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
#ifndef LIBBITCOIN_CHAIN_OPERATION_HPP
#define LIBBITCOIN_CHAIN_OPERATION_HPP

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <vector>
#include <bitcoin/bitcoin/chain/script/opcode.hpp>
#include <bitcoin/bitcoin/chain/script/operation_iterator.hpp>
#include <bitcoin/bitcoin/chain/script/script_pattern.hpp>
#include <bitcoin/bitcoin/define.hpp>
#include <bitcoin/bitcoin/math/elliptic_curve.hpp>
#include <bitcoin/bitcoin/utility/data.hpp>
#include <bitcoin/bitcoin/utility/reader.hpp>
#include <bitcoin/bitcoin/utility/writer.hpp>

namespace libbitcoin {
namespace chain {

class BC_API operation
{
public:
    typedef std::vector<operation> stack;

    // Constructors.
    //-------------------------------------------------------------------------

    operation();

    operation(operation&& other);
    operation(const operation& other);

    // TODO: just use from_data?
    operation(data_chunk&& data);
    operation(const data_chunk& data);

    // Operators.
    //-------------------------------------------------------------------------

    operation& operator=(operation&& other);
    operation& operator=(const operation& other);

    bool operator==(const operation& other) const;
    bool operator!=(const operation& other) const;

    // Deserialization.
    //-------------------------------------------------------------------------

    static operation factory_from_data(const data_chunk& data);
    static operation factory_from_data(std::istream& stream);
    static operation factory_from_data(reader& source);

    bool from_data(const data_chunk& data);
    bool from_data(std::istream& stream);
    bool from_data(reader& source);

    bool from_string(const std::string& mnemonic);

    bool is_valid() const;

    // Serialization.
    //-------------------------------------------------------------------------

    void to_data(std::ostream& stream) const;
    void to_data(writer& sink) const;
    data_chunk to_data() const;

    std::string to_string(uint32_t active_forks) const;

    // Iteration.
    //-------------------------------------------------------------------------

    operation_iterator begin() const;
    operation_iterator end() const;

    // Properties (size, accessors, cache).
    //-------------------------------------------------------------------------

    uint64_t serialized_size() const;

    /// Get the op code [0..255], if is_valid is consistent with data.
    opcode code() const;

    /// This should not be used to set a data code (as it will set invalid).
    void set_code(opcode code);

    /// Get the data, empty if not a push code or if invalid.
    const data_chunk& data() const;

    /// These select the minimal code for the data (sets invalid on overflow).
    void set_data(data_chunk&& data);
    void set_data(const data_chunk& data);

    // Utilities.
    //-------------------------------------------------------------------------

    /// Compute the minimal data opcode for a given size.
    static opcode opcode_from_size(size_t size);

    /// Convert the opcode to a number (or max_uint8 if not nonnegative number).
    static uint8_t opcode_to_positive(opcode code);

    /// Types of opcodes.
    static bool is_push(opcode code);
    static bool is_counted(opcode code);
    static bool is_positive(opcode code);
    static bool is_disabled(opcode code);
    static bool is_conditional(opcode code);

    /// stack factories
    static stack to_null_data_pattern(data_slice data);
    static stack to_pay_multisig_pattern(uint8_t signatures, const point_list& points);
    static stack to_pay_multisig_pattern(uint8_t signatures, const data_stack& points);
    static stack to_pay_public_key_pattern(data_slice point);
    static stack to_pay_key_hash_pattern(const short_hash& hash);
    static stack to_pay_script_hash_pattern(const short_hash& hash);

    // Validation.
    //-------------------------------------------------------------------------

    bool is_disabled() const;
    bool is_oversized() const;

protected:
    operation(opcode code, data_chunk&& data, bool valid);
    operation(opcode code, const data_chunk& data, bool valid);

    void reset();

private:
    static uint32_t read_data_size(uint8_t byte, reader& source);

    opcode code_;
    data_chunk data_;
    bool valid_;
};

} // end chain
} // end libbitcoin

#endif
