"""get-item-projection-expression-alias-substitution-exceeds-4kb-accepted."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-item-projection-expression-alias-substitution-exceeds-4kb-accepted"
GROUP = "validation"
SERVICES = ["dynamodb"]

_N = 20
_NAME_LEN = 250


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """GetItem accepts a ProjectionExpression whose raw string stays under the 4096-byte
    expression-size limit, even though its ExpressionAttributeNames placeholders substitute
    to attribute names that together total well over 4096 bytes.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ServiceQuotas.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-expr-alias-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table),
                              "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 1, "MaxAttempts": 60})

    names = {}
    item = {"pk": {"S": "p1"}}
    for i in range(_N):
        prefix = f"n{i}_"
        long_name = prefix + ("a" * (_NAME_LEN - len(prefix)))
        assert len(long_name) == _NAME_LEN, f"built name of {len(long_name)} bytes, wanted {_NAME_LEN}"
        names[f"#a{i}"] = long_name
        item[long_name] = {"S": f"v{i}"}
    item["excluded"] = {"S": "not-projected"}
    ddb.put_item(TableName=table, Item=item)

    expr = ",".join(f"#a{i}" for i in range(_N))
    substituted_total = sum(len(v) for v in names.values())
    assert len(expr) < 4096, f"raw ProjectionExpression is {len(expr)} bytes, expected well under 4096"
    assert substituted_total > 4096, (
        f"substituted attribute names total {substituted_total} bytes, expected well over 4096"
    )

    resp = ddb.get_item(
        TableName=table, Key={"pk": {"S": "p1"}}, ProjectionExpression=expr,
        ExpressionAttributeNames=names, ConsistentRead=True,
    )
    got = resp["Item"]
    assert "excluded" not in got, f"expected 'excluded' excluded by the projection, got keys={sorted(got)}"
    assert "pk" not in got, f"expected key attribute 'pk' excluded when not named in ProjectionExpression, got keys={sorted(got)}"
    assert set(got) == set(names.values()), (
        f"expected exactly the {_N} aliased attributes projected, got keys={sorted(got)}"
    )
    for i in range(_N):
        attr = names[f"#a{i}"]
        assert got[attr] == {"S": f"v{i}"}, f"expected {attr}={{'S': 'v{i}'}}, got {got.get(attr)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
