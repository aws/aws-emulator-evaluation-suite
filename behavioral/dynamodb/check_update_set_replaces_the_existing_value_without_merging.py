"""update-set-replaces-the-existing-value-without-merging."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-set-replaces-the-existing-value-without-merging"
GROUP = "expressions"
SERVICES = ["dynamodb"]

# (stored value, value SET over it)
_OVER = {
    "s-to-n": ({"S": "x"}, {"N": "5"}),
    "m-to-m": ({"M": {"a": {"S": "1"}}}, {"M": {"b": {"S": "2"}}}),
    "m-nested": ({"M": {"a": {"M": {"x": {"S": "1"}}}}}, {"M": {"a": {"M": {"y": {"S": "2"}}}}}),
    "l-to-m": ({"L": [{"S": "1"}]}, {"M": {"b": {"S": "2"}}}),
    "l-to-l": ({"L": [{"S": "1"}, {"S": "2"}]}, {"L": [{"S": "3"}]}),
}


def _teardown(undo, *not_found, timeout_s=300.0):
    """A cleanup running undo() where a failed delete raises; in-use is retried every 2 s."""
    def run_undo():
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                undo()
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code in not_found:
                    return
                if code != "ResourceInUseException" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)
    return run_undo


def _wait_active(ddb, ctx, table):
    """Poll DescribeTable every 2 s until the table and its indexes are ACTIVE."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE" and all(
            g.get("IndexStatus") == "ACTIVE" for g in desc.get("GlobalSecondaryIndexes", [])
        ):
            return desc
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE before the deadline: {desc!r}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """UpdateItem SET over an attribute the item holds replaces the whole value (S to N, map to map,
    nested map, list to map, list to list), alone or with an ADD in the same update; no merge.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.UpdateExpressions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-set-replace-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    for case, (old, new) in _OVER.items():
        for with_add in (False, True):
            key = {"pk": {"S": f"{case}-{'add' if with_add else 'alone'}"}}
            ddb.put_item(TableName=table, Item={**key, "s": old, "keep": {"S": "k"}})
            names = {"#s": "s"}
            values = {":s": new}
            expression = "SET #s = :s"
            if with_add:
                names["#n"] = "n"
                values[":one"] = {"N": "1"}
                expression += " ADD #n :one"
            ddb.update_item(TableName=table, Key=key, UpdateExpression=expression,
                            ExpressionAttributeNames=names, ExpressionAttributeValues=values)
            got = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
            want = {**key, "s": new, "keep": {"S": "k"}}
            if with_add:
                want["n"] = {"N": "1"}
            assert got == want, f"{expression!r} over s = {old!r} left {got!r}, expected {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
