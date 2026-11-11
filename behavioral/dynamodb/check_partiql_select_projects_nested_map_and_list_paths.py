"""partiql-select-projects-nested-map-and-list-paths."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partiql-select-projects-nested-map-and-list-paths"
GROUP = "partiql"
SERVICES = ["dynamodb"]


def _error(fn):
    """(code, message) of the ClientError fn() raises; raises if the call unexpectedly succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"call unexpectedly succeeded where an error was required: {resp!r}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PartiQL SELECT of a nested map path, a list index and a list index inside a map returns
    each leaf keyed by its last path segment, or one attribute-less item when every path is
    absent; two selected paths sharing a last segment are refused.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.select.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbsel-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 1, "MaxAttempts": 60})

    statement = f'SELECT m.a.b, l[1], m.l[0].x FROM "{table}" WHERE pk = ?'

    # 1. Every named path present: each returns under its own last segment, nothing else.
    ddb.put_item(
        TableName=table,
        Item={
            "pk": {"S": "full"},
            "m": {"M": {
                "a": {"M": {"b": {"S": "ab-val"}}},
                "l": {"L": [{"M": {"x": {"S": "mlx0"}, "b": {"S": "mlb0"}}}]},
            }},
            "l": {"L": [{"N": "100"}, {"N": "200"}]},
        },
    )
    full = ddb.execute_statement(
        Statement=statement, Parameters=[{"S": "full"}], ConsistentRead=True
    )["Items"]
    want_full = [{"b": {"S": "ab-val"}, "l[1]": {"N": "200"}, "x": {"S": "mlx0"}}]
    assert full == want_full, f"SELECT over a fully-populated item returned {full!r}, expected {want_full!r}"

    # 2. None of the named paths present (the top-level attributes don't exist at all): one item,
    # no attributes — never an error, never an empty result set.
    ddb.put_item(TableName=table, Item={"pk": {"S": "missing"}, "keep": {"S": "k"}})
    missing = ddb.execute_statement(
        Statement=statement, Parameters=[{"S": "missing"}], ConsistentRead=True
    )["Items"]
    assert missing == [{}], f"SELECT with every path absent returned {missing!r}, expected [{{}}]"

    # 3. A mix: the map path exists, the list and the nested list do not.
    ddb.put_item(
        TableName=table,
        Item={"pk": {"S": "partial"}, "m": {"M": {"a": {"M": {"b": {"S": "partial-b"}}}}}},
    )
    partial = ddb.execute_statement(
        Statement=statement, Parameters=[{"S": "partial"}], ConsistentRead=True
    )["Items"]
    assert partial == [{"b": {"S": "partial-b"}}], (
        f"SELECT with only m.a.b present returned {partial!r}, expected only b"
    )

    # 4. Two selected paths that share a last segment are rejected outright, not silently merged.
    code, message = _error(lambda: ddb.execute_statement(
        Statement=f'SELECT m.a.b, m.l[0].b FROM "{table}" WHERE pk = ?',
        Parameters=[{"S": "full"}],
        ConsistentRead=True,
    ))
    assert code == "ValidationException", f"duplicate select identifiers answered {code!r}, expected ValidationException"
    assert message == "Duplicate identifiers in select clause: b", f"refusal message was {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
