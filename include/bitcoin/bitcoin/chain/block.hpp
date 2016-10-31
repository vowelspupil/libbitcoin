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
#ifndef LIBBITCOIN_CHAIN_BLOCK_HPP
#define LIBBITCOIN_CHAIN_BLOCK_HPP

#include <cstddef>
#include <cstdint>
#include <istream>
#include <memory>
#include <string>
#include <vector>
#include <bitcoin/bitcoin/chain/chain_state.hpp>
#include <bitcoin/bitcoin/chain/header.hpp>
#include <bitcoin/bitcoin/chain/transaction.hpp>
#include <bitcoin/bitcoin/define.hpp>
#include <bitcoin/bitcoin/error.hpp>
#include <bitcoin/bitcoin/math/hash.hpp>
#include <bitcoin/bitcoin/math/hash_number.hpp>
#include <bitcoin/bitcoin/utility/data.hpp>
#include <bitcoin/bitcoin/utility/reader.hpp>
#include <bitcoin/bitcoin/utility/writer.hpp>

namespace libbitcoin {
namespace chain {

class BC_API block
{
public:
    typedef std::vector<block> list;
    typedef std::vector<size_t> indexes;

    // validation-related
    typedef transaction::sets_const_ptr input_sets;

    // These properties facilitate block validation.
    // This validation data is not copied on block copy.
    struct validation
    {
        code result = error::not_found;
        chain_state::ptr state = nullptr;
        transaction::sets_const_ptr sets = nullptr;
    };

    // Constructors.
    //-------------------------------------------------------------------------

    block();

    block(block&& other);
    block(const block& other);

    block(chain::header&& header, transaction::list&& transactions);
    block(const chain::header& header, const transaction::list& transactions);

    // Operators.
    //-------------------------------------------------------------------------

    /// This class is move assignable but NOT copy assignable.
    block& operator=(block&& other);
    block& operator=(const block& other) = delete;

    bool operator==(const block& other) const;
    bool operator!=(const block& other) const;

    // Deserialization.
    //-------------------------------------------------------------------------

    static block factory_from_data(const data_chunk& data);
    static block factory_from_data(std::istream& stream);
    static block factory_from_data(reader& source);

    bool from_data(const data_chunk& data);
    bool from_data(std::istream& stream);
    bool from_data(reader& source);

    bool is_valid() const;

    // Serialization.
    //-------------------------------------------------------------------------

    data_chunk to_data() const;
    void to_data(std::ostream& stream) const;
    void to_data(writer& sink) const;

    input_sets to_input_sets(size_t fanout, bool with_coinbase=true) const;

    // Properties (size, accessors, cache).
    //-------------------------------------------------------------------------

    uint64_t serialized_size() const;

    // deprecated (unsafe)
    chain::header& header();

    const chain::header& header() const;
    void set_header(const chain::header& value);
    void set_header(chain::header&& value);

    // deprecated (unsafe)
    transaction::list& transactions();

    const transaction::list& transactions() const;
    void set_transactions(const transaction::list& value);
    void set_transactions(transaction::list&& value);

    hash_digest hash() const;

    // Utilities.
    //-------------------------------------------------------------------------

    static block genesis_mainnet();
    static block genesis_testnet();
    static size_t locator_size(size_t top);
    static indexes locator_heights(size_t top);

    // Validation.
    //-------------------------------------------------------------------------

    static uint64_t subsidy(size_t height);
    static hash_number difficulty(uint32_t bits);

    uint64_t fees() const;
    uint64_t claim() const;
    uint64_t reward(size_t height) const;
    hash_number difficulty() const;
    hash_digest generate_merkle_root() const;
    size_t signature_operations() const;
    size_t signature_operations(bool bip16_active) const;
    size_t total_inputs(bool with_coinbase=true) const;

    bool is_extra_coinbases() const;
    bool is_final(size_t height) const;
    bool is_distinct_transaction_set() const;
    bool is_valid_coinbase_claim(size_t height) const;
    bool is_valid_coinbase_script(size_t height) const;
    bool is_valid_merkle_root() const;

    code check() const;
    code check_transactions() const;
    code accept() const;
    code accept(const chain_state& state) const;
    code accept_transactions(const chain_state& state) const;
    code connect() const;
    code connect(const chain_state& state) const;
    code connect_transactions(const chain_state& state) const;

    // These fields do not participate in serialization or comparison.
    mutable validation validation;

protected:
    void reset();

private:
    chain::header header_;
    transaction::list transactions_;
};

} // namespace chain
} // namespace libbitcoin

#endif
