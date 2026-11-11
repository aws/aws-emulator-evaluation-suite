"""tag-resource-nonexistent-stream-arn-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-nonexistent-stream-arn-rejected"
GROUP = "tagging"
SERVICES = ["dynamodb"]

_CLEANUP_S = 250.0  # under the suite's 300 s cleanup budget


def _tag_op(fn):
    """Run a tagging call, retried while a previous tag update on the table is still settling."""
    deadline = time.monotonic() + 120.0
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "LimitExceededException" or time.monotonic() >= deadline:
                raise
        time.sleep(3)


def _tags_of(ddb, arn) -> dict:
    return {t["Key"]: t["Value"] for t in _tag_op(lambda: ddb.list_tags_of_resource(ResourceArn=arn))["Tags"]}


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _error(fn):
    """(code, message) of the ClientError fn() raises; raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected {code!r}, got {got_code!r} ({got_message!r})"
    assert got_message == message, f"unexpected message {got_message!r}"


def _delete_table(ddb, table_name) -> None:
    """Delete the table; retry ResourceInUseException while a tag update settles, gone is done."""
    deadline = time.monotonic() + _CLEANUP_S
    while True:
        try:
            ddb.delete_table(TableName=table_name)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource and ListTagsOfResource on a well-formed but nonexistent stream ARN under a real
    table raise ResourceNotFoundException naming that ARN, while the table's real stream ARN
    accepts a tag.
    """
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-ddb-strmtag404-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_IMAGE"},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table(ddb, table_name))
    ddb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    desc = ddb.describe_table(TableName=table_name)["Table"]
    table_arn, stream_arn = desc["TableArn"], desc["LatestStreamArn"]

    # Positive control: the real stream ARN accepts a tag.
    _tag_op(lambda: ddb.tag_resource(ResourceArn=stream_arn, Tags=[{"Key": "scope", "Value": "stream"}]))
    stream_tags = _poll_until(
        lambda: _tags_of(ddb, stream_arn),
        lambda d: d.get("scope") == "stream",
        description="positive-control stream tag visible",
    )
    assert stream_tags == {"scope": "stream"}, f"expected the positive-control tag, got {stream_tags!r}"

    fake_stream_arn = table_arn + "/stream/2000-01-01T00:00:00.000"
    not_found = (
        "ResourceNotFoundException",
        f"Requested resource not found: ResourceArn: {fake_stream_arn} not found",
    )
    expect_error(
        lambda: _tag_op(lambda: ddb.tag_resource(ResourceArn=fake_stream_arn, Tags=[{"Key": "k", "Value": "v"}])),
        *not_found,
    )
    expect_error(
        lambda: _tag_op(lambda: ddb.list_tags_of_resource(ResourceArn=fake_stream_arn)),
        *not_found,
    )

    # The rejected calls touched nothing: the real stream's tags are unchanged.
    stream_tags_after = _tags_of(ddb, stream_arn)
    assert stream_tags_after == {"scope": "stream"}, (
        f"expected the real stream's tags unchanged by the rejected calls, got {stream_tags_after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
