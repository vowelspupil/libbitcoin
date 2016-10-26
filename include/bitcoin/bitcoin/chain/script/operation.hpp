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

    static const size_t max_null_data_size;

    // Constructors.
    //-------------------------------------------------------------------------

    operation();

    operation(operation&& other);
    operation(const operation& other);

    operation(opcode code, data_chunk&& data);
    operation(opcode code, const data_chunk& data);

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

    bool is_valid() const;

    // Serialization.
    //-------------------------------------------------------------------------

    data_chunk to_data() const;
    void to_data(std::ostream& stream) const;
    void to_data(writer& sink) const;

    std::string to_string(uint32_t flags) const;

    // Properties (size, accessors, cache).
    //-------------------------------------------------------------------------

    uint64_t serialized_size() const;

    opcode code() const;
    void set_code(opcode code);

    // deprecated (unsafe)
    data_chunk& data();

    const data_chunk& data() const;
    void set_data(data_chunk&& data);
    void set_data(const data_chunk& data);

    // Utilities.
    //-------------------------------------------------------------------------

    static uint8_t decode_op_n(opcode code);

    static opcode opcode_from_byte(uint8_t byte);
    static opcode opcode_from_data_size(size_t size);

    static uint8_t opcode_to_byte(opcode code);
    static uint8_t opcode_to_byte(const operation& op);

    /// Types of opcodes.
    static bool is_op_n(opcode code);
    static bool is_push(opcode code);
    static bool is_disabled(opcode code);
    static bool is_conditional(opcode code);
    static bool is_operational(opcode code);
    static bool is_executable( opcode code);
    static bool is_push_only(const operation::stack& operations);

    /// unspendable pattern (standard)
    static bool is_null_data_pattern(const operation::stack& ops);

    /// payment script patterns (standard)
    static bool is_pay_multisig_pattern(const operation::stack& ops);
    static bool is_pay_public_key_pattern(const operation::stack& ops);
    static bool is_pay_key_hash_pattern(const operation::stack& ops);
    static bool is_pay_script_hash_pattern(const operation::stack& ops);

    /// signature script patterns (standard)
    static bool is_sign_multisig_pattern(const operation::stack& ops);
    static bool is_sign_public_key_pattern(const operation::stack& ops);
    static bool is_sign_key_hash_pattern(const operation::stack& ops);
    static bool is_sign_script_hash_pattern(const operation::stack& ops);

    /// stack factories
    static stack to_null_data_pattern(data_slice data);
    static stack to_pay_multisig_pattern(uint8_t signatures,
        const point_list& points);
    static stack to_pay_multisig_pattern(uint8_t signatures,
        const data_stack& points);
    static stack to_pay_public_key_pattern(data_slice point);
    static stack to_pay_key_hash_pattern(const short_hash& hash);
    static stack to_pay_script_hash_pattern(const short_hash& hash);

protected:
    void reset();

private:
    static size_t read_data_size(uint8_t byte, reader& source);

    opcode code_;
    data_chunk data_;
};

} // end chain
} // end libbitcoin

#endif
