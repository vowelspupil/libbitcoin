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
#include <boost/test/unit_test.hpp>
#include <bitcoin/bitcoin.hpp>

using namespace bc;
using namespace bc::chain;

#define SOURCE "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f00000015"
static const auto valid_raw_operation_iterator_source = to_chunk(base16_literal(SOURCE));

BOOST_AUTO_TEST_SUITE(operation_iterator_tests)

BOOST_AUTO_TEST_CASE(operation_iterator__operator_bool__not_at_end__returns_true)
{
    operation_iterator instance(operation{});
    BOOST_REQUIRE((bool)instance);
}

BOOST_AUTO_TEST_CASE(operation_iterator__operator_bool_at_end__returns_false)
{
    operation_iterator instance(operation{}, true);
    BOOST_REQUIRE(!(bool)instance);
}

BOOST_AUTO_TEST_CASE(operation_iterator__operator_asterisk__initialized_op__matches_source)
{
    operation op;
    BOOST_REQUIRE(op.from_data(valid_raw_operation_iterator_source));
    operation_iterator instance(op);

    for (size_t i = 0; i < valid_raw_operation_iterator_source.size(); i++)
    {
        BOOST_REQUIRE((bool)instance);
        BOOST_REQUIRE_EQUAL(valid_raw_operation_iterator_source[i], (*instance));
        instance++;
    }

    BOOST_REQUIRE(!instance);
    BOOST_REQUIRE_EQUAL(0u, (*instance));
}

BOOST_AUTO_TEST_CASE(operation_iterator__operator_arrow__initialized_op__matches_source)
{
    operation op;
    BOOST_REQUIRE(op.from_data(valid_raw_operation_iterator_source));
    operation_iterator instance(op);
    BOOST_REQUIRE(valid_raw_operation_iterator_source.size() > 0);

    for (size_t i = 0; i < valid_raw_operation_iterator_source.size(); i++)
    {
        BOOST_REQUIRE((bool)instance);
        BOOST_REQUIRE_EQUAL(valid_raw_operation_iterator_source[i], instance.operator->());
        instance++;
    }

    BOOST_REQUIRE(!instance);
    BOOST_REQUIRE_EQUAL(0u, instance.operator->());
}

BOOST_AUTO_TEST_CASE(operation_iterator__operator_plus_minus_int__roundtrip__success)
{
    operation op;
    uint8_t offset = 5u;
    BOOST_REQUIRE(op.from_data(valid_raw_operation_iterator_source));

    operation_iterator instance(op, offset);
    operation_iterator expected(instance);

    auto initial = instance++;
    BOOST_REQUIRE(instance != expected);
    BOOST_REQUIRE(initial == expected);

    auto modified = instance--;
    BOOST_REQUIRE(instance == expected);
    BOOST_REQUIRE(modified != expected);
}

BOOST_AUTO_TEST_CASE(operation_iterator__operator_plus_minus__roundtrip__success)
{
    operation op;
    uint8_t offset = 5u;
    BOOST_REQUIRE(op.from_data(valid_raw_operation_iterator_source));

    operation_iterator instance(op, offset);
    operation_iterator expected(instance);

    ++instance;
    BOOST_REQUIRE(instance != expected);

    --instance;
    BOOST_REQUIRE(instance == expected);
}

BOOST_AUTO_TEST_SUITE_END()
