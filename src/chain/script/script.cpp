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
#include <bitcoin/bitcoin/chain/script/script.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <numeric>
#include <sstream>
#include <utility>
#include <bitcoin/bitcoin/constants.hpp>
#include <bitcoin/bitcoin/chain/script/interpreter.hpp>
#include <bitcoin/bitcoin/chain/script/opcode.hpp>
#include <bitcoin/bitcoin/chain/script/operation.hpp>
#include <bitcoin/bitcoin/chain/script/rule_fork.hpp>
#include <bitcoin/bitcoin/chain/script/script_pattern.hpp>
#include <bitcoin/bitcoin/chain/script/sighash_algorithm.hpp>
#include <bitcoin/bitcoin/chain/transaction.hpp>
#include <bitcoin/bitcoin/error.hpp>
#include <bitcoin/bitcoin/formats/base_16.hpp>
#include <bitcoin/bitcoin/math/elliptic_curve.hpp>
#include <bitcoin/bitcoin/math/hash.hpp>
#include <bitcoin/bitcoin/utility/assert.hpp>
#include <bitcoin/bitcoin/utility/container_sink.hpp>
#include <bitcoin/bitcoin/utility/container_source.hpp>
#include <bitcoin/bitcoin/utility/istream_reader.hpp>
#include <bitcoin/bitcoin/utility/ostream_writer.hpp>
#include <bitcoin/bitcoin/utility/string.hpp>
#include <bitcoin/bitcoin/utility/variable_uint_size.hpp>

namespace libbitcoin {
namespace chain {

static const auto sighash_all = sighash_algorithm::all;
static const auto sighash_none = sighash_algorithm::none;
static const auto sighash_single = sighash_algorithm::single;
static const auto anyone_flag = sighash_algorithm::anyone_can_pay;

// bit.ly/2cPazSa
static const auto one_hash = hash_literal(
    "0000000000000000000000000000000000000000000000000000000000000001");

// Constructors.
//-----------------------------------------------------------------------------

// A default instance is invalid (until modified).
script::script()
  : valid_(false), cached_(false)
{
}

script::script(script&& other)
  : bytes_(std::move(other.bytes_)), valid_(other.valid_), cached_(false)
{
    // TODO: implement safe private accessor for conditional cache transfer.
}

script::script(const script& other)
  : bytes_(other.bytes_), valid_(other.valid_), cached_(false)
{
    // TODO: implement safe private accessor for conditional cache transfer.
}

script::script(const operation_stack& ops)
{
    valid_ = from_stack(ops);
}

script::script(operation_stack&& ops)
{
    valid_ = from_stack(ops);
}

script::script(data_chunk&& bytes, bool prefix)
{
    if (prefix)
    {
        // TODO: store prefix in bytes_ to simplify and optimize this.
        valid_ = from_data(bytes, prefix);
        return;
    }

    bytes_ = std::move(bytes);
    valid_ = true;
}

script::script(const data_chunk& bytes, bool prefix)
{
    valid_ = from_data(bytes, prefix);
}

// Operators.
//-----------------------------------------------------------------------------

script& script::operator=(script&& other)
{
    // TODO: implement safe private accessor for conditional cache transfer.
    reset();
    bytes_ = std::move(other.bytes_);
    valid_ = other.valid_;
    return *this;
}

script& script::operator=(const script& other)
{
    // TODO: implement safe private accessor for conditional cache transfer.
    reset();
    bytes_ = other.bytes_;
    valid_ = other.valid_;
    return *this;
}

bool script::operator==(const script& other) const
{
    return bytes_ == other.bytes_;
}

bool script::operator!=(const script& other) const
{
    return !(*this == other);
}

// Deserialization.
//-----------------------------------------------------------------------------

// static
script script::factory_from_data(const data_chunk& data, bool prefix)
{
    script instance;
    instance.from_data(data, prefix);
    return instance;
}

// static
script script::factory_from_data(std::istream& stream, bool prefix)
{
    script instance;
    instance.from_data(stream, prefix);
    return instance;
}

// static
script script::factory_from_data(reader& source, bool prefix)
{
    script instance;
    instance.from_data(source, prefix);
    return instance;
}

bool script::from_data(const data_chunk& data, bool prefix)
{
    data_source istream(data);
    return from_data(istream, prefix);
}

bool script::from_data(std::istream& stream, bool prefix)
{
    istream_reader source(stream);
    return from_data(source, prefix);
}

bool script::from_data(reader& source, bool prefix)
{
    reset();
    valid_ = true;

    bytes_ = prefix ?
        source.read_bytes(source.read_size_little_endian()) :
        source.read_bytes();

    if (!source)
        reset();

    return source;
}

bool script::from_string(const std::string& mnemonic)
{
    reset();

    // There is strictly one operation per string token.
    const auto tokens = split(mnemonic);
    operation_stack ops;
    ops.resize(tokens.size());

    // Create an op stack from the split tokens, one operation per token.
    for (size_t index = 0; index < ops.size(); ++index)
        if (!ops[index].from_string(tokens[index]))
            return false;

    return from_stack(ops);
}

bool script::from_stack(const operation_stack& ops)
{
    reset();
    valid_ = true;

    if (!stack_to_data(bytes_, ops))
    {
        reset();
        return false;
    }

    stack_ = ops;
    cached_ = true;
    return true;
}

// private/static
bool script::stack_to_data(data_chunk& out, const operation_stack& ops)
{
    data_chunk data;
    data.reserve(serialized_size(ops));

    for (const auto& op: ops)
    {
        const auto operation = op.to_data();
        
        if (!op.is_valid())
            return false;

        out.insert(out.end(), operation.begin(), operation.end());
    }

    BITCOIN_ASSERT(out.size() == serialized_size(ops));
    out = std::move(data);
    return true;
}

// private/static
size_t script::serialized_size(const operation_stack& ops)
{
    const auto op_size = [](size_t total, const operation& op)
    {
        return total + op.serialized_size();
    };

    return std::accumulate(ops.begin(), ops.end(), size_t{0}, op_size);
}

// protected
void script::reset()
{
    bytes_.clear();
    bytes_.shrink_to_fit();
    valid_ = false;
    cached_ = false;
    stack_.clear();
    stack_.shrink_to_fit();
}

bool script::is_valid() const
{
    // All script bytes are valid under some circumstance (e.g. coinbase).
    // This returns false if a prefix and byte count does not match.
    return valid_;
}

bool script::is_valid_stack() const
{
    // Script validity is independent of individual operation validity.
    // There is a trailing invalid/default op if a push op had a size mismatch.
    return stack().empty() || stack_.back().is_valid();
}

// Serialization.
//-----------------------------------------------------------------------------

data_chunk script::to_data(bool prefix) const
{
    data_chunk data;
    data.reserve(serialized_size(prefix));
    data_sink ostream(data);
    to_data(ostream, prefix);
    ostream.flush();
    BITCOIN_ASSERT(data.size() == serialized_size(prefix));
    return data;
}

void script::to_data(std::ostream& stream, bool prefix) const
{
    ostream_writer sink(stream);
    to_data(sink, prefix);
}

void script::to_data(writer& sink, bool prefix) const
{
    // TODO: optimize by always storing the prefixed serialization.
    if (prefix)
        sink.write_variable_little_endian(satoshi_content_size());

    sink.write_bytes(bytes_);
}

std::string script::to_string(uint32_t active_forks) const
{
    auto first = true;
    std::ostringstream text;

    for (const auto& op: stack())
    {
        text << (first ? "" : " ") << op.to_string(active_forks);
        first = false;
    }

    // An invalid operation has a specialized serialization.
    return text.str();
}

// Iteration.
//-----------------------------------------------------------------------------
// The first stack access must be method-based to guarantee the cache.

bool script::empty() const
{
    return stack().empty();
}

size_t script::size() const
{
    return stack().size();
}

const operation& script::front() const
{
    BITCOIN_ASSERT(!stack().empty());
    return stack().front();
}

const operation& script::back() const
{
    BITCOIN_ASSERT(!stack().empty());
    return stack().back();
}

const operation& script::operator[](std::size_t index) const
{
    BITCOIN_ASSERT(index < stack().size());
    return stack()[index];
}

operation::const_iterator script::begin() const
{
    return stack().begin();
}

operation::const_iterator script::end() const
{
    return stack().end();
}

// Properties (size, accessors, cache).
//-----------------------------------------------------------------------------

uint64_t script::satoshi_content_size() const
{
    return bytes_.size();
}

uint64_t script::serialized_size(bool prefix) const
{
    auto size = satoshi_content_size();

    if (prefix)
        size += variable_uint_size(size);

    return size;
}

// protected
const data_chunk& script::bytes() const
{
    return bytes_;
}

// protected
const operation_stack& script::stack() const
{
    ///////////////////////////////////////////////////////////////////////////
    // Critical Section
    mutex_.lock_upgrade();

    if (cached_)
    {
        mutex_.unlock_upgrade();
        //---------------------------------------------------------------------
        return stack_;
    }

    operation op;
    data_source istream(bytes_);
    istream_reader source(istream);
    const auto size = bytes_.size();

    //+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    mutex_.unlock_upgrade_and_lock();

    // One operation per byte is the upper limit of operations.
    stack_.reserve(size);

    // If an op fails it is placed on the stack and the loop terminates.
    // To validate the ops the caller must test the last op.is_valid().
    // This is not necessary during script validation as it is autmoatic.
    while (!source.is_exhausted())
    {
        op.from_data(source);
        stack_.push_back(std::move(op));
    }

    stack_.shrink_to_fit();
    cached_ = true;

    mutex_.unlock();
    ///////////////////////////////////////////////////////////////////////////

    return stack_;
}

// Signing.
//-----------------------------------------------------------------------------

inline sighash_algorithm to_sighash_enum(uint8_t sighash_type)
{
    return static_cast<sighash_algorithm>(
        sighash_type & sighash_algorithm::mask);
}

inline uint8_t is_sighash_enum(uint8_t sighash_type,
    sighash_algorithm value)
{
    return to_sighash_enum(sighash_type) == value;
}

inline bool is_sighash_flag(uint8_t sighash_type,
    sighash_algorithm value)
{
    return (sighash_type & value) != 0;
}

static hash_digest sign_none(const transaction& tx, uint32_t input_index,
    const script& script_code, uint8_t sighash_type, bool anyone)
{
    input::list ins;
    const auto& inputs = tx.inputs();
    ins.reserve(anyone ? 1 : inputs.size());

    BITCOIN_ASSERT(input_index < inputs.size());
    const auto& self = inputs[input_index];

    if (anyone)
    {
        // Retain only self.
        ins.emplace_back(self.previous_output(), script_code, self.sequence());
    }
    else
    {
        // Erase all input scripts and sequences.
        for (const auto& input: inputs)
            ins.emplace_back(input.previous_output(), script{}, 0);

        // Replace self that is lost in the loop.
        ins[input_index].set_script(script_code);
        ins[input_index].set_sequence(self.sequence());
    }

    // Move new inputs to new transaction and drop outputs.
    return transaction(tx.version(), tx.locktime(), std::move(ins),
        output::list{}).hash(sighash_type);
}

static hash_digest sign_single(const transaction& tx, uint32_t input_index,
    const script& script_code, uint8_t sighash_type, bool anyone)
{
    input::list ins;
    const auto& inputs = tx.inputs();
    ins.reserve(anyone ? 1 : inputs.size());

    BITCOIN_ASSERT(input_index < inputs.size());
    const auto& self = inputs[input_index];

    if (anyone)
    {
        // Retain only self.
        ins.emplace_back(self.previous_output(), script_code, self.sequence());
    }
    else
    {
        // Erase all input scripts and sequences.
        for (const auto& input: inputs)
            ins.emplace_back(input.previous_output(), script{}, 0);

        // Replace self that is lost in the loop.
        ins[input_index].set_script(script_code);
        ins[input_index].set_sequence(self.sequence());
    }

    // Trim and clear outputs except that of specified input index.
    const auto& outputs = tx.outputs();
    output::list outs(input_index + 1);

    BITCOIN_ASSERT(input_index < outputs.size());
    outs.back() = outputs[input_index];

    // Move new inputs and new outputs to new transaction.
    return transaction(tx.version(), tx.locktime(), std::move(ins),
        std::move(outs)).hash(sighash_type);
}

static hash_digest sign_all(const transaction& tx, uint32_t input_index,
    const script& script_code, uint8_t sighash_type, bool anyone)
{
    input::list ins;
    const auto& inputs = tx.inputs();
    ins.reserve(anyone ? 1 : inputs.size());

    BITCOIN_ASSERT(input_index < inputs.size());
    const auto& self = inputs[input_index];

    if (anyone)
    {
        // Retain only self.
        ins.emplace_back(self.previous_output(), script_code, self.sequence());
    }
    else
    {
        // Erase all input scripts.
        for (const auto& input: inputs)
            ins.emplace_back(input.previous_output(), script{},
                input.sequence());

        // Replace self that is lost in the loop.
        ins[input_index].set_script(script_code);
        ////ins[input_index].set_sequence(self.sequence());
    }

    // Move new inputs and copy outputs to new transaction.
    transaction out(tx.version(), tx.locktime(), input::list{}, tx.outputs());
    out.set_inputs(std::move(ins));
    return out.hash(sighash_type);
}

static script strip_code_seperators(const script& script_code)
{
    operation_stack ops;

    for (auto op = script_code.begin(); op != script_code.end(); ++op)
        if (op->code() != opcode::codeseparator)
            ops.push_back(*op);

    return script(std::move(ops));
}

// static
hash_digest script::generate_signature_hash(const transaction& tx,
    uint32_t input_index, const script& script_code, uint8_t sighash_type)
{
    const auto any = is_sighash_flag(sighash_type, anyone_flag);
    const auto single = is_sighash_enum(sighash_type, sighash_single);

    if (input_index >= tx.inputs().size() || 
        (input_index >= tx.outputs().size() && single))
    {
        //*********************************************************************
        // Wacky satoshi consensus behavior we must perpetuate.
        //*********************************************************************
        return one_hash;
    }

    //*************************************************************************
    // More wacky satoshi consensus behavior we must perpetuate.
    //*************************************************************************
    const auto stripped = strip_code_seperators(script_code);

    switch (to_sighash_enum(sighash_type))
    {
        case sighash_none:
            return sign_none(tx, input_index, stripped, sighash_type, any);
        case sighash_single:
            return sign_single(tx, input_index, stripped, sighash_type, any);
        default:
        case sighash_all:
            return sign_all(tx, input_index, stripped, sighash_type, any);
    }
}

// static
bool script::check_signature(const ec_signature& signature,
    uint8_t sighash_type, const data_chunk& public_key,
    const script& script_code, const transaction& tx, uint32_t input_index)
{
    if (public_key.empty())
        return false;

    // This always produces a valid signature hash, including one_hash.
    const auto sighash = script::generate_signature_hash(tx, input_index,
        script_code, sighash_type);

    // Validate the EC signature.
    return verify_signature(public_key, sighash, signature);
}

// static
bool script::create_endorsement(endorsement& out, const ec_secret& secret,
    const script& prevout_script, const transaction& tx, uint32_t input_index,
    uint8_t sighash_type)
{
    // This always produces a valid signature hash, including one_hash.
    const auto sighash = script::generate_signature_hash(tx, input_index,
        prevout_script, sighash_type);

    // Create the EC signature and encode as DER.
    ec_signature signature;
    if (!sign(signature, secret, sighash) || !encode_signature(out, signature))
        return false;

    // Add the sighash type to the end of the DER signature -> endorsement.
    out.push_back(sighash_type);
    return true;
}

// Utilities.
//-----------------------------------------------------------------------------

// static
// Test rule_fork flag for a given context.
bool script::is_enabled(uint32_t flags, rule_fork flag)
{
    return (flag & flags) != 0;
}

bool script::is_push_data_only() const
{
    return is_push_only(stack());
}

script_pattern script::pattern() const
{
    // The first stack access must be method-based to guarantee the cache.
    if (is_null_data_pattern(stack()))
        return script_pattern::null_data;

    if (is_pay_multisig_pattern(stack_))
        return script_pattern::pay_multisig;

    if (is_pay_public_key_pattern(stack_))
        return script_pattern::pay_public_key;

    if (is_pay_key_hash_pattern(stack_))
        return script_pattern::pay_key_hash;

    if (is_pay_script_hash_pattern(stack_))
        return script_pattern::pay_script_hash;

    if (is_sign_multisig_pattern(stack_))
        return script_pattern::sign_multisig;

    if (is_sign_public_key_pattern(stack_))
        return script_pattern::sign_public_key;

    if (is_sign_key_hash_pattern(stack_))
        return script_pattern::sign_key_hash;

    if (is_sign_script_hash_pattern(stack_))
        return script_pattern::sign_script_hash;

    return script_pattern::non_standard;
}

inline size_t multisig_or_default_sigops(bool enabled, opcode last)
{
    return enabled && operation::is_positive(last) ?
        operation::opcode_to_positive(last) : multisig_default_sigops;
}

// See BIP16.
// TODO: distinct cache property for serialized_script total.
size_t script::sigops(bool serialized_script) const
{
    size_t total = 0;
    auto preceding = opcode::reserved_255;

    // The first stack access must be method-based to guarantee the cache.
    for (const auto& op: stack())
    {
        const auto code = op.code();

        if (code == opcode::checksig || code == opcode::checksigverify)
        {
            total++;
        }
        else if (code == opcode::checkmultisig || 
            code == opcode::checkmultisigverify)
        {
            total += multisig_or_default_sigops(serialized_script, preceding);
        }

        preceding = code;
    }

    return total;
}

// See BIP16.
// TODO: cache (default to max_size_t sentinel).
size_t script::pay_script_hash_sigops(const script& prevout) const
{
    // The prevout script is not p2sh, so no signature increment.
    if (prevout.pattern() != script_pattern::pay_script_hash)
        return 0;

    // The first stack access must be method-based to guarantee the cache.
    // Conditions added by EKV on 2016.09.15 for safety and BIP16 consistency.
    // Only push data operations allowed in script, so no signature increment.
    if (stack().empty() || !is_push_data_only())
        return 0;

    script eval;

    // Treat failure as zero signatures (data).
    if (!eval.from_data(stack_.back().data(), false))
        return 0;

    // Count the sigops in the serialized script using BIP16 rules.
    return eval.sigops(true);
}

bool script::is_pay_to_script_hash(uint32_t flags) const
{
    return (is_enabled(flags, rule_fork::bip16_rule) &&
        (pattern() == script_pattern::pay_script_hash));
}

// Validation.
//-----------------------------------------------------------------------------
// static

// TODO: return detailed result code indicating failure condition.
code script::verify(const transaction& tx, uint32_t input_index,
    uint32_t flags)
{
    if (input_index >= tx.inputs().size())
        return error::operation_failed;

    // Obtain the previous output script from the cached previous output.
    auto& prevout = tx.inputs()[input_index].previous_output().validation;
    return verify(tx, input_index, prevout.cache.script(), flags);
}

// TODO: return detailed result code indicating failure condition.
code script::verify(const transaction& tx, uint32_t input_index,
    const script& prevout_script, uint32_t flags)
{
    if (input_index >= tx.inputs().size())
        return error::operation_failed;

    // Create a context for evaluation of the input script.
    evaluation_context input_context(flags);
    const auto& input_script = tx.inputs()[input_index].script();

    // Evaluate the input script.
    if (!interpreter::run(tx, input_index, input_script, input_context))
        return error::validate_inputs_failed;

    // Copy the input context stack for evaluation of the prevout script.
    evaluation_context out_context(flags, input_context.stack);

    // Evaluate the output script.
    if (!interpreter::run(tx, input_index, prevout_script, out_context))
        return error::validate_inputs_failed;

    // Return if stack is false.
    if (!out_context.stack_result())
        return error::validate_inputs_failed;

    // If the previout script is not p2sh with bip16 enabled we are done.
    if (!prevout_script.is_pay_to_script_hash(flags))
        return error::success;

    // Additional validation for bip16 pay-to-script-hash script.
    return pay_hash(tx, input_index, input_script, input_context);
}

// private
code script::pay_hash(const transaction& tx, uint32_t input_index,
    const script& input_script, evaluation_context& input_context)
{
    // Only push data operations allowed in script.
    if (!input_script.is_push_data_only())
        return error::validate_inputs_failed;

    // Use the last stack item as the serialized script.
    // input_context.stack cannot be empty here because out_context is true.
    const auto& serialized = input_context.stack.back();
    script eval;

    // Always process a serialized script as fallback since it can be data.
    if (!eval.from_data(serialized, false))
        return error::validate_inputs_failed;

    // Pop last item and use popped stack for evaluation of the eval script.
    input_context.stack.pop_back();
    const auto flags = input_context.flags();
    evaluation_context eval_context(flags, input_context.stack);

    // Evaluate the eval (serialized) script.
    if (!interpreter::run(tx, input_index, eval, eval_context))
        return error::validate_inputs_failed;

    // Return the stack state.
    return eval_context.stack_result() ? error::success :
        error::validate_inputs_failed;
}

} // namespace chain
} // namespace libbitcoin
