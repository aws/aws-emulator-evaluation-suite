"""execute-statement-number-literal-exponent-and-leading-dot-forms."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "execute-statement-number-literal-exponent-and-leading-dot-forms"
GROUP = "partiql"
SERVICES = ["dynamodb"]


def _insert(ddb, table_name, pk, n_literal):
    ddb.execute_statement(
        Statement=f"INSERT INTO \"{table_name}\" VALUE {{'pk': '{pk}', 'n': {n_literal}}}"
    )


def _select_one(ddb, table_name, n_literal):
    items = ddb.execute_statement(
        Statement=f'SELECT * FROM "{table_name}" WHERE n = {n_literal}',
        ConsistentRead=True,
    )["Items"]
    assert len(items) == 1, f"literal {n_literal!r} matched {len(items)} items, expected exactly 1"
    return items[0]


@tags("axis:happy-path", "cap:c2", "concern:representation", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteStatement number literals accept exponent and leading-dot forms and compare equal
    to the canonical N they denote; an INSERTed literal of either form stores that canonical N.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.insert.html
    """
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-ddb-tbl-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    ddb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 30})

    # A canonical N 7310000, and two signed canonical Ns (7.3 and -7.3) that the leading-dot
    # exponent forms below must resolve to, each written with an unadorned decimal literal.
    _insert(ddb, table_name, "base", "7310000")
    _insert(ddb, table_name, "pos", "7.3")
    _insert(ddb, table_name, "neg", "-7.3")

    for literal in ("7.31e6", "7.31E6", "7.31e+6", "731e4", "73100000e-1"):
        item = _select_one(ddb, table_name, literal)
        assert item["pk"] == {"S": "base"}, (
            f"literal {literal!r} matched pk {item['pk']!r}, expected the 7310000 item"
        )
        assert item["n"] == {"N": "7310000"}, (
            f"literal {literal!r} matched an n of {item['n']!r}, expected the canonical N 7310000"
        )

    pos_item = _select_one(ddb, table_name, ".73e1")
    assert pos_item["pk"] == {"S": "pos"}, (
        f"literal '.73e1' matched pk {pos_item['pk']!r}, expected the 7.3 item"
    )
    assert pos_item["n"] == {"N": "7.3"}, f"literal '.73e1' matched n {pos_item['n']!r}, expected N 7.3"

    neg_item = _select_one(ddb, table_name, "-.73e1")
    assert neg_item["pk"] == {"S": "neg"}, (
        f"literal '-.73e1' matched pk {neg_item['pk']!r}, expected the -7.3 item"
    )
    assert neg_item["n"] == {"N": "-7.3"}, f"literal '-.73e1' matched n {neg_item['n']!r}, expected N -7.3"

    # An INSERTed exponent or leading-dot literal is itself canonicalized before it is stored.
    _insert(ddb, table_name, "ins1", "7.32e6")
    stored1 = ddb.get_item(
        TableName=table_name, Key={"pk": {"S": "ins1"}}, ConsistentRead=True
    )["Item"]
    assert stored1["n"] == {"N": "7320000"}, (
        f"INSERT of 7.32e6 stored n as {stored1['n']!r}, expected the canonical N 7320000"
    )

    _insert(ddb, table_name, "ins2", ".7325e1")
    stored2 = ddb.get_item(
        TableName=table_name, Key={"pk": {"S": "ins2"}}, ConsistentRead=True
    )["Item"]
    assert stored2["n"] == {"N": "7.325"}, (
        f"INSERT of .7325e1 stored n as {stored2['n']!r}, expected the canonical N 7.325"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
