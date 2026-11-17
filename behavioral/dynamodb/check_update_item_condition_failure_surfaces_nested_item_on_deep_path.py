"""update-item-condition-failure-surfaces-nested-item-on-deep-path."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-condition-failure-surfaces-nested-item-on-deep-path"
GROUP = "conditions"
SERVICES = ["dynamodb"]
_CONDITIONAL_CHECK_FAILED = ("ConditionalCheckFailedException", "The conditional request failed")


def _teardown(undo, *not_found, timeout_s=300.0):
    """Run undo() where a failed delete raises; ResourceInUse is retried to the deadline."""
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


def _wait_active(ddb, table, timeout_s=300.0):
    """Poll DescribeTable every 2 s until ACTIVE, or fail with the last status read."""
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE":
            return
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE before the deadline: {desc!r}")


def expect_error(fn, code, message):
    """Call fn() and grade the ClientError it raises on exact code and message; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] == code, f"expected code {code!r}, got {err['Code']!r}: {err.get('Message')!r}"
        assert err["Message"] == message, f"expected message {message!r}, got {err['Message']!r}"
        return exc
    raise AssertionError(f"expected {code} {message!r}, but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A rejected UpdateItem whose ConditionExpression checks a deep map leaf surfaces, via
    ReturnValuesOnConditionCheckFailure=ALL_OLD, the CURRENT whole item with its nested map and
    list intact, exactly as a successful ALL_OLD would, and leaves the item unchanged.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_UpdateItem.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-rvccfe-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, table)

    key = {"pk": {"S": "rv-ccfe"}}
    item = {
        **key,
        "deep": {"M": {"leaf": {"N": "1"}, "other": {"S": "x"}}},
        "lst": {"L": [{"S": "a0"}, {"S": "a1"}]},
    }
    ddb.put_item(TableName=table, Item=item)

    # Positive control: a condition on the CURRENT deep leaf value succeeds and also advances
    # that same leaf, so the value the next step's condition checks is genuinely stale.
    ddb.update_item(
        TableName=table, Key=key,
        UpdateExpression="SET deep.leaf = :v, side = :s",
        ConditionExpression="deep.leaf = :expected",
        ExpressionAttributeValues={":v": {"N": "2"}, ":s": {"S": "control"}, ":expected": {"N": "1"}},
    )
    controlled = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert controlled.get("side") == {"S": "control"}, (
        f"the positive control update did not take effect, got {controlled!r}"
    )
    assert controlled["deep"]["M"]["leaf"] == {"N": "2"}, (
        f"the positive control update must have advanced deep.leaf to 2, got {controlled!r}"
    )

    # Break exactly one thing: the condition checks the now-STALE deep.leaf value (1, not 2).
    exc = expect_error(
        lambda: ddb.update_item(
            TableName=table, Key=key,
            UpdateExpression="SET side = :s",
            ConditionExpression="deep.leaf = :expected",
            ExpressionAttributeValues={":s": {"S": "clobbered"}, ":expected": {"N": "1"}},
            ReturnValuesOnConditionCheckFailure="ALL_OLD",
        ),
        *_CONDITIONAL_CHECK_FAILED,
    )
    surfaced = exc.response["Item"]
    assert surfaced == controlled, (
        f"ReturnValuesOnConditionCheckFailure=ALL_OLD on a deep-path condition must surface the "
        f"whole current item with its nested map and list intact, got {surfaced!r}, expected {controlled!r}"
    )

    # Effect absent: an independent read shows the rejected update did not touch the item.
    unchanged = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert unchanged == controlled, f"a rejected conditional update must not modify the item, got {unchanged!r}"

    # Restore: the identical call, with the condition matching the CURRENT value, now succeeds.
    ddb.update_item(
        TableName=table, Key=key,
        UpdateExpression="SET side = :s",
        ConditionExpression="deep.leaf = :expected",
        ExpressionAttributeValues={":s": {"S": "restored"}, ":expected": {"N": "2"}},
        ReturnValuesOnConditionCheckFailure="ALL_OLD",
    )
    restored = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert restored.get("side") == {"S": "restored"}, (
        f"an UpdateItem whose deep-path condition matches the current value must succeed, got {restored!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
