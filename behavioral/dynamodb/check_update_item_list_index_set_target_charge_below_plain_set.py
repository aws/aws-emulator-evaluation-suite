"""update-item-list-index-set-target-charge-below-plain-set."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-list-index-set-target-charge-below-plain-set"
GROUP = "limits"
SERVICES = ["dynamodb"]

_OVER_LIMIT = ("ValidationException", "Item size to update has exceeded the maximum allowed size")
_UPPER_BOUND = 410 * 1024
_DELTA_FROM_PLAIN_SET = 5


def _code_and_message(fn):
    """The botocore (code, message) *fn* raises; an unexpected success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a refusal, but the call succeeded: {result!r}")


def _accepted(ddb, table: str, pk: str, expr: str, values: dict) -> bool:
    """Seed pk with pk + an existing one-element list "d", then attempt one UpdateItem."""
    ddb.put_item(TableName=table, Item={"pk": {"S": pk}, "d": {"L": [{"S": "z"}]}})
    try:
        ddb.update_item(TableName=table, Key={"pk": {"S": pk}}, UpdateExpression=expr,
                         ExpressionAttributeValues=values)
        return True
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if (err.get("Code"), err.get("Message")) == _OVER_LIMIT:
            return False
        raise


def _bisect(ddb, table: str, expr_fn, pk_source) -> tuple[int, int]:
    """(largest accepted n, smallest refused n) for the clause expr_fn(n) builds."""
    lo, hi = 1, _UPPER_BOUND
    while hi - lo > 1:
        mid = (lo + hi) // 2
        expr, values = expr_fn(mid)
        if _accepted(ddb, table, next(pk_source), expr, values):
            lo = mid
        else:
            hi = mid
    return lo, hi


def _create_table(ctx, ddb, name: str) -> None:
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 30})


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem's size ceiling for a list-index SET target sits a fixed number of bytes
    below a plain whole-attribute SET's ceiling on the same pre-existing one-element list.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ServiceQuotas.html#limits-items
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddblistidx-")
    _create_table(ctx, ddb, table)
    pk_source = iter(f"{i:08d}" for i in range(1, 1_000_000))

    plain_lo, plain_hi = _bisect(ddb, table, lambda n: ("SET v = :v", {":v": {"S": "x" * n}}), pk_source)
    assert plain_hi == plain_lo + 1, f"plain SET bisection did not converge: lo={plain_lo} hi={plain_hi}"

    idx_lo, idx_hi = _bisect(ddb, table, lambda n: ("SET d[0] = :v", {":v": {"S": "x" * n}}), pk_source)
    assert idx_hi == idx_lo + 1, f"list-index SET bisection did not converge: lo={idx_lo} hi={idx_hi}"

    # Measured relative to the plain whole-attribute SET boundary on the same preexisting item.
    assert plain_lo - idx_lo == _DELTA_FROM_PLAIN_SET, (
        f"list-index SET ceiling {idx_lo} was {plain_lo - idx_lo} byte(s) below the plain SET "
        f"ceiling {plain_lo}, expected {_DELTA_FROM_PLAIN_SET}"
    )

    # Positive control: the accepted list-index boundary actually lands at that index, and the
    # next byte up leaves the existing element untouched -- proven by a read.
    accepted_pk = next(pk_source)
    ddb.put_item(TableName=table, Item={"pk": {"S": accepted_pk}, "d": {"L": [{"S": "z"}]}})
    ddb.update_item(TableName=table, Key={"pk": {"S": accepted_pk}}, UpdateExpression="SET d[0] = :v",
                     ExpressionAttributeValues={":v": {"S": "x" * idx_lo}})
    accepted_item = ddb.get_item(TableName=table, Key={"pk": {"S": accepted_pk}}, ConsistentRead=True)["Item"]
    accepted_elem = accepted_item["d"]["L"][0]["S"]
    assert len(accepted_elem) == idx_lo, (
        f"the accepted {idx_lo}-byte list-index SET did not read back at that length: {accepted_elem!r}"
    )

    refused_pk = next(pk_source)
    ddb.put_item(TableName=table, Item={"pk": {"S": refused_pk}, "d": {"L": [{"S": "z"}]}})
    got = _code_and_message(lambda: ddb.update_item(
        TableName=table, Key={"pk": {"S": refused_pk}}, UpdateExpression="SET d[0] = :v",
        ExpressionAttributeValues={":v": {"S": "x" * idx_hi}}))
    assert got == _OVER_LIMIT, f"refusal at {idx_hi} bytes was {got!r}, expected {_OVER_LIMIT!r}"
    refused_item = ddb.get_item(TableName=table, Key={"pk": {"S": refused_pk}}, ConsistentRead=True)["Item"]
    assert refused_item["d"]["L"][0]["S"] == "z", (
        f"a refused list-index SET must leave the existing element untouched, got {refused_item!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
