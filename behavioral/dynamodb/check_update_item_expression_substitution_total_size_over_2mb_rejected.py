"""update-item-expression-substitution-total-size-over-2mb-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-expression-substitution-total-size-over-2mb-rejected"
GROUP = "limits"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"
KB = 1024
_TWO_MB = 2 * 1024 * 1024
_UNDER_HALF = 950 * KB
_OVER_FILLER = 490 * KB
_OVER_COUNT = 6


def _code(fn) -> tuple[str, str]:
    """The botocore error code and message *fn* raises.

    An unexpected success raises rather than returning None.
    """
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An UpdateItem whose ExpressionAttributeValues total just under 2 MB, split across its
    ConditionExpression and UpdateExpression, is evaluated and applies; the same shape with the
    substitution total over 2 MB is refused with ValidationException and the item is unchanged.
    """
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=t, Item={"pk": {"S": "row"}, "marker": {"S": "initial"}})

    # Split the substitution budget across ConditionExpression's :vc and UpdateExpression's
    # :vu (a DELETE from a set attribute that does not exist, so it writes nothing) so neither
    # expression alone needs to carry the whole total; both the OR and the DELETE are no-ops on
    # the outcome and exist only to make every placeholder referenced exactly once.
    under_values = {
        ":m": {"S": "written"},
        ":vc": {"S": "c" * _UNDER_HALF},
        ":vu": {"SS": ["u" * _UNDER_HALF]},
    }
    under_total = len(under_values[":vc"]["S"]) + len(under_values[":vu"]["SS"][0]) + len(under_values[":m"]["S"])
    assert under_total < _TWO_MB, f"the under-cap request totals {under_total} bytes, not under 2 MB"
    ddb.update_item(
        TableName=t,
        Key={"pk": {"S": "row"}},
        UpdateExpression="SET marker = :m DELETE tags :vu",
        ConditionExpression="attribute_exists(pk) OR pk = :vc",
        ExpressionAttributeValues=under_values,
    )
    got = ddb.get_item(TableName=t, Key={"pk": {"S": "row"}}, ConsistentRead=True).get("Item") or {}
    assert got.get("marker", {}).get("S") == "written", (
        f"an UpdateItem whose substitution values total {under_total} bytes (< 2 MB) must be "
        f"evaluated and applied, got marker={got.get('marker')!r}"
    )
    assert "tags" not in got, f"DELETE from a never-created set attribute must not create it, got {got!r}"

    over_values = {f":o{i}": {"S": chr(ord("a") + i) * _OVER_FILLER} for i in range(_OVER_COUNT)}
    over_values[":m2"] = {"S": "written2"}
    pairs = " OR ".join(f":o{i} = :o{i + 1}" for i in range(0, _OVER_COUNT, 2))
    over_total = sum(len(over_values[f":o{i}"]["S"]) for i in range(_OVER_COUNT)) + len(over_values[":m2"]["S"])
    assert over_total > _TWO_MB, f"the over-cap request totals {over_total} bytes, not over 2 MB"
    code, message = _code(lambda: ddb.update_item(
        TableName=t,
        Key={"pk": {"S": "row"}},
        UpdateExpression="SET marker = :m2",
        ConditionExpression=f"attribute_exists(pk) OR {pairs}",
        ExpressionAttributeValues=over_values,
    ))
    assert code == ERR_VALIDATION, (
        f"an UpdateItem whose substitution values total {over_total} bytes (> 2 MB) must be "
        f"{ERR_VALIDATION}, got {code!r}: {message!r}"
    )
    assert message == "1 validation error detected: ExpressionAttributeValues exceeds max size", (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )
    unchanged = ddb.get_item(TableName=t, Key={"pk": {"S": "row"}}, ConsistentRead=True).get("Item") or {}
    assert unchanged.get("marker", {}).get("S") == "written", (
        f"the refused over-2MB UpdateItem must leave the item unchanged, got marker="
        f"{unchanged.get('marker')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
