"""scan-totalsegments-above-the-model-maximum-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scan-totalsegments-above-the-model-maximum-rejected"
GROUP = "scan"
SERVICES = ["dynamodb"]

_ABOVE_MAX = (
    "ValidationException",
    "1 validation error detected: Value at 'TotalSegments' failed to satisfy constraint: "
    "Member must have value less than or equal to 1000000",
)


def _client_error(fn):
    """Return the botocore Error dict for a call real AWS refuses.

    Raises on unexpected success, so accepting invalid input fails distinctly.
    """
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS refuses this Scan, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Scan's TotalSegments above its maximum of 1,000,000 is refused with ValidationException,
    TotalSegments at exactly 1,000,000 is accepted, and the refusal changes nothing.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Scan.html#Scan.ParallelScan
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-tsmax-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=table, Item={"pk": {"S": "anchor"}})

    # --- positive control: the maximum itself (1,000,000) is accepted ---
    at_max = ddb.scan(TableName=table, TotalSegments=1_000_000, Segment=0, ConsistentRead=True)
    assert at_max["ScannedCount"] == 0, (
        f"TotalSegments=1000000 Segment=0 of a 1-item table must be accepted; got "
        f"{at_max['ScannedCount']!r} scanned"
    )

    # --- the refusal: one past the maximum ---
    err = _client_error(lambda: ddb.scan(
        TableName=table, TotalSegments=1_000_001, Segment=0, ConsistentRead=True,
    ))
    assert err.get("Code") == _ABOVE_MAX[0], (
        f"TotalSegments=1000001 must be refused with {_ABOVE_MAX[0]!r}; got "
        f"{err.get('Code')!r} / {err.get('Message')!r}"
    )
    assert err.get("Message") == _ABOVE_MAX[1], (
        f"expected message {_ABOVE_MAX[1]!r}, got {err.get('Message')!r}"
    )

    # --- effect-absent: the refused call created and deleted nothing ---
    after = ddb.scan(TableName=table, ConsistentRead=True)
    assert after["Count"] == 1 and after["Items"] == [{"pk": {"S": "anchor"}}], (
        f"the refused Scan must not change the table; an unsegmented Scan now returns "
        f"{after['Items']!r}, expected only the anchor item"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
