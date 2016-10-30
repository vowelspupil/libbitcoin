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
#ifndef LIBBITCOIN_CHAIN_SCRIPT_HPP
#define LIBBITCOIN_CHAIN_SCRIPT_HPP

#include <cstddef>
#include <cstdint>
#include <istream>
#include <string>
#include <bitcoin/bitcoin/define.hpp>
#include <bitcoin/bitcoin/error.hpp>
#include <bitcoin/bitcoin/chain/script/evaluation_context.hpp>
#include <bitcoin/bitcoin/chain/script/operation.hpp>
#include <bitcoin/bitcoin/chain/script/operation_iterator.hpp>
#include <bitcoin/bitcoin/chain/script/rule_fork.hpp>
#include <bitcoin/bitcoin/chain/script/script_pattern.hpp>
#include <bitcoin/bitcoin/math/elliptic_curve.hpp>
#include <bitcoin/bitcoin/utility/data.hpp>
#include <bitcoin/bitcoin/utility/reader.hpp>
#include <bitcoin/bitcoin/utility/writer.hpp>

namespace libbitcoin {
namespace chain {

class BC_API transaction;

class BC_API script
{
public:
    static const size_t max_null_data_size;

    // Constructors.
    //-------------------------------------------------------------------------

    script();

    script(script&& other);
    script(const script& other);

    script(data_chunk&& bytes);
    script(const data_chunk& bytes);

    // TODO: create ops cache.
    script(operation::stack&& ops);
    script(const operation::stack& ops);

    // Operators.
    //-------------------------------------------------------------------------

    script& operator=(script&& other);
    script& operator=(const script& other);

    bool operator==(const script& other) const;
    bool operator!=(const script& other) const;

    // Deserialization.
    //-------------------------------------------------------------------------

    static script factory_from_data(const data_chunk& data, bool prefix);
    static script factory_from_data(std::istream& stream, bool prefix);
    static script factory_from_data(reader& source, bool prefix);

    /// Deserialization invalidates the iterator.
    bool from_data(const data_chunk& data, bool prefix);
    bool from_data(std::istream& stream, bool prefix);
    bool from_data(reader& source, bool prefix);

    /// Deserialization invalidates the iterator.
    bool from_string(const std::string& mnemonic);
    bool from_stack(const operation::stack& ops);

    bool is_valid() const;

    // Serialization.
    //-------------------------------------------------------------------------

    data_chunk to_data(bool prefix) const;
    void to_data(std::ostream& stream, bool prefix) const;
    void to_data(writer& sink, bool prefix) const;

    std::string to_string(uint32_t active_forks) const;
    operation::stack to_stack() const;

    // Iteration.
    //-------------------------------------------------------------------------

    operation_iterator begin() const;
    operation_iterator end() const;

    // Properties (size, accessors, cache).
    //-------------------------------------------------------------------------

    uint64_t satoshi_content_size() const;
    uint64_t serialized_size(bool prefix) const;

    const data_chunk& bytes() const;

    /// Assignment invalidates the iterator.
    void set_bytes(data_chunk&& bytes);
    void set_bytes(const data_chunk& bytes);

    // Signing.
    //-------------------------------------------------------------------------

    static hash_digest generate_signature_hash(const transaction& tx,
        uint32_t input_index, const script& script_code, uint8_t sighash_type);

    static bool check_signature(const ec_signature& signature,
        uint8_t sighash_type, const data_chunk& public_key,
        const script& script_code, const transaction& tx,
        uint32_t input_index);

    static bool create_endorsement(endorsement& out, const ec_secret& secret,
        const script& prevout_script, const transaction& tx,
        uint32_t input_index, uint8_t sighash_type);

    // Utilities.
    //-------------------------------------------------------------------------

    static bool is_enabled(uint32_t active_forks, rule_fork flag);

    script_pattern pattern() const;
    size_t sigops(bool serialized_script) const;
    size_t pay_script_hash_sigops(const script& prevout) const;

    // Validation.
    //-------------------------------------------------------------------------

    static code verify(const transaction& tx, uint32_t input_index,
        uint32_t flags);

    static code verify(const transaction& tx, uint32_t input_index,
        const script& prevout_script, uint32_t flags);

protected:
    void reset();

    /// Used in all signature script patterns.
    bool is_push_only() const;

    /// Unspendable pattern (standard).
    bool is_null_data_pattern(const operation::stack& ops) const;

    /// Payment script patterns (standard).
    bool is_pay_multisig_pattern(const operation::stack& ops) const;
    bool is_pay_public_key_pattern(const operation::stack& ops) const;
    bool is_pay_key_hash_pattern(const operation::stack& ops) const;
    bool is_pay_script_hash_pattern(const operation::stack& ops) const;

    /// Signature script patterns (standard).
    bool is_sign_multisig_pattern(const operation::stack& ops) const;
    bool is_sign_public_key_pattern(const operation::stack& ops) const;
    bool is_sign_key_hash_pattern(const operation::stack& ops) const;
    bool is_sign_script_hash_pattern(const operation::stack& ops) const;

private:
    static size_t script_size(const operation::stack& ops);
    static data_chunk to_bytes(const operation::stack& ops);
    static code pay_hash(const transaction& tx, uint32_t input_index,
        const script& input_script, evaluation_context& input_context);

    bool is_pay_to_script_hash(uint32_t flags) const;

    data_chunk bytes_;
    bool valid_;
};

} // namespace chain
} // namespace libbitcoin

#endif
