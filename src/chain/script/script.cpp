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
#include <numeric>
#include <sstream>
#include <utility>
#include <bitcoin/bitcoin/constants.hpp>
#include <bitcoin/bitcoin/chain/script/interpreter.hpp>
#include <bitcoin/bitcoin/chain/script/opcode.hpp>
#include <bitcoin/bitcoin/chain/script/operation.hpp>
#include <bitcoin/bitcoin/chain/script/operation_iterator.hpp>
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

// This is policy, not consensus.
const size_t script::max_null_data_size = 80;

// Fixed tuning parameter.
static constexpr size_t stack_capactity = 10;

// Constructors.
//-----------------------------------------------------------------------------

// A default instance is invalid (until modified).
script::script()
  : valid_(false)
{
}

script::script(script&& other)
  : bytes_(std::move(other.bytes_)), valid_(other.valid_)
{
}

script::script(const script& other)
  : bytes_(other.bytes_), valid_(other.valid_)
{
}

script::script(data_chunk&& bytes)
  : bytes_(std::move(bytes)), valid_(true)
{
}

script::script(const data_chunk& bytes)
  : bytes_(bytes), valid_(true)
{
}

script::script(const operation::stack& ops)
  : bytes_(to_bytes(ops)), valid_(true)
{
}

// TODO: create ops cache.
script::script(operation::stack&& ops)
  : bytes_(to_bytes(ops)), valid_(true)
{
}

// Operators.
//-----------------------------------------------------------------------------

script& script::operator=(script&& other)
{
    bytes_ = std::move(other.bytes_);
    valid_ = other.valid_;
    return *this;
}

script& script::operator=(const script& other)
{
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

    if (prefix)
        source.read_bytes(source.read_size_little_endian());
    else
        source.read_bytes();

    if (!source)
        reset();

    return source;
}

// There is strictly one operation per string token.
bool script::from_string(const std::string& mnemonic)
{
    reset();

    const auto tokens = split(mnemonic);
    operation::stack ops;
    ops.resize(tokens.size());

    for (size_t index = 0; index < ops.size(); ++index)
        if (!ops[index].from_string(tokens[index]))
            return false;

    return from_stack(ops);
}

// private/static
size_t script::script_size(const operation::stack& ops)
{
    const auto op_size = [](size_t total, const operation& op)
    {
        return total + op.serialized_size();
    };

    return std::accumulate(ops.begin(), ops.end(), size_t{0}, op_size);
}

// private/static
data_chunk script::to_bytes(const operation::stack& ops)
{
    const auto bytes = script_size(ops);

    data_chunk script;
    script.reserve(bytes);

    for (const auto& op: ops)
    {
        const auto bytes = op.to_data();
        script.insert(script.end(), bytes.begin(), bytes.end());
    }

    BITCOIN_ASSERT(bytes == script.size());
    return script;
}

bool script::from_stack(const operation::stack& ops)
{
    set_bytes(to_bytes(ops));
    return true;
}

// protected
void script::reset()
{
    bytes_.clear();
    bytes_.shrink_to_fit();
    valid_ = false;
}

bool script::is_valid() const
{
    return valid_ || !bytes_.empty();
}

// Serialization.
//-----------------------------------------------------------------------------

data_chunk script::to_data(bool prefix) const
{
    data_chunk data;
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
    if (prefix)
        sink.write_variable_little_endian(satoshi_content_size());

    sink.write_bytes(bytes_);
}

std::string script::to_string(uint32_t active_forks) const
{
    auto first = true;
    std::ostringstream text;

    for (const auto& op: to_stack())
    {
        text << (first ? "" : " ") << op.to_string(active_forks);
        first = false;
    }

    return text.str();
}

operation::stack script::to_stack() const
{
    operation op;
    operation::stack stack;
    stack.reserve(stack_capactity);

    data_source istream(bytes_);
    istream_reader source(istream);

    while (op.from_data(source))
        stack.push_back(op);

    stack.shrink_to_fit();
    return stack;
}

// Iteration.
//-----------------------------------------------------------------------------

operation_iterator script::begin() const
{
    return operation_iterator(bytes_);
}

operation_iterator script::end() const
{
    return operation_iterator(bytes_, true);
}

// Properties (size, accessors, cache).
//-----------------------------------------------------------------------------

// TODO: cache.
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

const data_chunk& script::bytes() const
{
    return bytes_;
}

void script::set_bytes(data_chunk&& bytes)
{
    valid_ = true;
    bytes_ = std::move(bytes);
}

void script::set_bytes(const data_chunk& bytes)
{
    valid_ = true;
    bytes_ = bytes;
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

// static
hash_digest script::generate_signature_hash(const transaction& tx,
    uint32_t input_index, const script& script_code, uint8_t sighash_type)
{
    const auto any = is_sighash_flag(sighash_type, anyone_flag);
    const auto single = is_sighash_enum(sighash_type, sighash_single);

    // Bounds are verified here and therefore only asserted in the helpers.
    if (input_index >= tx.inputs().size() || 
        (input_index >= tx.outputs().size() && single))
    {
        // Wacky satoshi consensus behavior we must perpetuate.
        return one_hash;
    }

    // Strip code seperators.
    // Wacky satoshi consensus behavior we must perpetuate.
    operation::stack ops;
    for (auto op = script_code.begin(); op != script_code.end(); ++op)
        if (op->code() != opcode::codeseparator)
            ops.push_back(*op);

    script stripped(std::move(ops));
    switch (to_sighash_enum(sighash_type))
    {
        case sighash_none:
            return sign_none(tx, input_index, script_code, sighash_type, any);

        case sighash_single:
            return sign_single(tx, input_index, script_code, sighash_type, any);

        default:
        case sighash_all:
            return sign_all(tx, input_index, script_code, sighash_type, any);
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

// Utilities: pattern comparisons.
// ----------------------------------------------------------------------------
// protected

bool script::is_push_only() const
{
    const operation::stack ops;

    const auto push = [](const operation& op)
    {
        return operation::is_push(op.code());
    };

    return std::all_of(begin(), end(), push);
}

// TODO: is a minimal data encoding required?
bool script::is_null_data_pattern(const operation::stack& ops) const
{
    return ops.size() == 2
        && ops[0].code() == opcode::return_
        && operation::is_push(ops[1].code())
        && ops[1].data().size() <= max_null_data_size;
}

bool script::is_pay_multisig_pattern(const operation::stack& ops) const
{
    static constexpr size_t op_1 = static_cast<uint8_t>(opcode::push_positive_1);
    static constexpr size_t op_16 = static_cast<uint8_t>(opcode::push_positive_16);

    const auto op_count = ops.size();

    if (op_count < 4 || ops[op_count - 1].code() != opcode::checkmultisig)
        return false;

    const auto op_m = static_cast<uint8_t>(ops[0].code());
    const auto op_n = static_cast<uint8_t>(ops[op_count - 2].code());

    if (op_m < op_1 || op_m > op_n || op_n < op_1 || op_n > op_16)
        return false;

    const auto number = op_n - op_1;
    const auto points = op_count - 3u;

    if (number != points)
        return false;

    for (auto op = ops.begin() + 1; op != ops.end() - 2; ++op)
        if (!is_public_key(op->data()))
            return false;

    return true;
}

// TODO: is a minimal data encoding required?
bool script::is_pay_public_key_pattern(const operation::stack& ops) const
{
    return ops.size() == 2
        && operation::is_push(ops[0].code())
        && is_public_key(ops[0].data())
        && ops[1].code() == opcode::checksig;
}

// TODO: is a minimal data encoding required?
bool script::is_pay_key_hash_pattern(const operation::stack& ops) const
{
    return ops.size() == 5
        && ops[0].code() == opcode::dup
        && ops[1].code() == opcode::hash160
        && operation::is_push(ops[2].code())
        && ops[2].data().size() == short_hash_size
        && ops[3].code() == opcode::equalverify
        && ops[4].code() == opcode::checksig;
}

// TODO: is a minimal data encoding required?
bool script::is_pay_script_hash_pattern(const operation::stack& ops) const
{
    return ops.size() == 3
        && ops[0].code() == opcode::hash160
        && operation::is_push(ops[1].code())
        && ops[1].data().size() == short_hash_size
        && ops[2].code() == opcode::equal;
}

// TODO: is a minimal data encoding required?
bool script::is_sign_multisig_pattern(const operation::stack& ops) const
{
    if (ops.size() < 2 || !is_push_only())
        return false;

    if (ops.front().code() != opcode::push_size_0)
        return false;

    return true;
}

// TODO: is a minimal data encoding required?
bool script::is_sign_public_key_pattern(const operation::stack& ops) const
{
    return ops.size() == 1 && is_push_only();
}

// TODO: is a minimal data encoding required?
bool script::is_sign_key_hash_pattern(const operation::stack& ops) const
{
    return ops.size() == 2 && is_push_only() &&
        is_public_key(ops.back().data());
}

// TODO: is a minimal data encoding required?
bool script::is_sign_script_hash_pattern(const operation::stack& ops) const
{
    if (ops.size() < 2 || !is_push_only())
        return false;

    const auto& redeem_data = ops.back().data();

    if (redeem_data.empty())
        return false;

    script redeem;

    if (!redeem.from_data(redeem_data, false))
        return false;

    // Is the redeem script a standard pay (output) script?
    const auto redeem_script_pattern = redeem.pattern();
    return redeem_script_pattern == script_pattern::pay_multisig
        || redeem_script_pattern == script_pattern::pay_public_key
        || redeem_script_pattern == script_pattern::pay_key_hash
        || redeem_script_pattern == script_pattern::pay_script_hash
        || redeem_script_pattern == script_pattern::null_data;
}

// Utilities.
//-----------------------------------------------------------------------------

// static
// Test rule_fork flag for a given context.
bool script::is_enabled(uint32_t flags, rule_fork flag)
{
    return (flag & flags) != 0;
}

script_pattern script::pattern() const
{
    // TODO: parse the operation stack, returning non_standard if fails.
    operation::stack ops;

    if (is_null_data_pattern(ops))
        return script_pattern::null_data;

    if (is_pay_multisig_pattern(ops))
        return script_pattern::pay_multisig;

    if (is_pay_public_key_pattern(ops))
        return script_pattern::pay_public_key;

    if (is_pay_key_hash_pattern(ops))
        return script_pattern::pay_key_hash;

    if (is_pay_script_hash_pattern(ops))
        return script_pattern::pay_script_hash;

    if (is_sign_multisig_pattern(ops))
        return script_pattern::sign_multisig;

    if (is_sign_public_key_pattern(ops))
        return script_pattern::sign_public_key;

    if (is_sign_key_hash_pattern(ops))
        return script_pattern::sign_key_hash;

    if (is_sign_script_hash_pattern(ops))
        return script_pattern::sign_script_hash;

    return script_pattern::non_standard;
}

// See BIP16.
// TODO: distinct cache property for serialized_script total.
size_t script::sigops(bool serialized_script) const
{
    size_t total = 0;
    opcode last_opcode = opcode::push_size_0;

    for (const auto& op: bytes_)
    {
        const auto code = op.code();

        if (code == opcode::checksig ||
            code == opcode::checksigverify)
        {
            total++;
        }
        else if (code == opcode::checkmultisig || 
            code == opcode::checkmultisigverify)
        {
            total += serialized_script && operation::is_positive(last_opcode) ?
                operation::opcode_to_positive(last_opcode) :
                multisig_default_signature_ops;
        }

        last_opcode = op.code();
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

    // Conditions added by EKV on 2016.09.15 for safety and BIP16 consistency.
    // Only push data operations allowed in script, so no signature increment.
    if (bytes_.empty() || !is_push_only())
        return 0;

    script eval;

    // Treat failure as zero signatures (data).
    if (!eval.from_data(bytes_.back().data(), false))
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
    if (!input_script.is_push_only())
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
