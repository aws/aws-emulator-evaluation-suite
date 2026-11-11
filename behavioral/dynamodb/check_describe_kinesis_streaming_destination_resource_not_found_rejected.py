"""describe-kinesis-streaming-destination-resource-not-found-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-kinesis-streaming-destination-resource-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeKinesisStreamingDestination on a fresh table returns no destinations, while on a nonexistent table it
    raises ResourceNotFoundException with the exact message.
    """
    ddb = ctx.client("dynamodb")

    table_name = ctx.unique_name("sim2real-notable-real-")
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _wait_table_active(ddb, table_name)

    real_dests = ddb.describe_kinesis_streaming_destination(TableName=table_name)[
        "KinesisDataStreamDestinations"
    ]
    assert real_dests == [], f"expected no streaming destinations on a fresh table, got {real_dests}"

    fake_table = ctx.unique_name("sim2real-notable-missing-")
    code, message = _error(
        lambda: ddb.describe_kinesis_streaming_destination(TableName=fake_table)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = f"Requested resource not found: Table: {fake_table} not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn):
    """(code, message) of the ClientError fn raises; an unexpected success raises AssertionError."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _wait_table_active(ddb, table_name, timeout_s=120, interval_s=3):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ddb.describe_table(TableName=table_name)["Table"]["TableStatus"]
        if last == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} never reached ACTIVE, last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
