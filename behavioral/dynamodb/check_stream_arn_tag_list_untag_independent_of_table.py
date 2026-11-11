"""stream-arn-tag-list-untag-independent-of-table."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stream-arn-tag-list-untag-independent-of-table"
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/ListTagsOfResource/UntagResource accept a table's stream ARN, and the tags they
    manage there stay entirely separate from the table's own tags, in both directions.
    """
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-ddb-strmtag-")
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
    assert stream_arn.startswith(table_arn + "/stream/"), (
        f"the stream ARN {stream_arn!r} is not nested under the table ARN {table_arn!r}"
    )

    _tag_op(lambda: ddb.tag_resource(ResourceArn=table_arn, Tags=[{"Key": "scope", "Value": "table-only"}]))
    table_tags = _poll_until(
        lambda: _tags_of(ddb, table_arn),
        lambda d: d.get("scope") == "table-only",
        description="table tag visible on ListTagsOfResource(table ARN)",
    )
    assert table_tags == {"sim2real": CHECK, "scope": "table-only"}, (
        f"expected only the create-time and table-only tags on the table, got {table_tags!r}"
    )

    _tag_op(lambda: ddb.tag_resource(ResourceArn=stream_arn, Tags=[{"Key": "scope", "Value": "stream-only"}]))
    stream_tags = _poll_until(
        lambda: _tags_of(ddb, stream_arn),
        lambda d: d.get("scope") == "stream-only",
        description="stream tag visible on ListTagsOfResource(stream ARN)",
    )
    assert stream_tags == {"scope": "stream-only"}, (
        f"expected ListTagsOfResource(stream ARN) to carry only the stream's own tag, got {stream_tags!r}"
    )

    table_tags_unaffected = _tags_of(ddb, table_arn)
    assert table_tags_unaffected == {"sim2real": CHECK, "scope": "table-only"}, (
        f"tagging the stream changed ListTagsOfResource(table ARN) to {table_tags_unaffected!r}"
    )

    _tag_op(lambda: ddb.untag_resource(ResourceArn=stream_arn, TagKeys=["scope"]))
    stream_tags_after = _poll_until(
        lambda: _tags_of(ddb, stream_arn),
        lambda d: "scope" not in d,
        description="stream tag removed from ListTagsOfResource(stream ARN)",
    )
    assert stream_tags_after == {}, (
        f"expected the stream's tags empty after UntagResource(stream ARN), got {stream_tags_after!r}"
    )

    table_tags_final = _tags_of(ddb, table_arn)
    assert table_tags_final == {"sim2real": CHECK, "scope": "table-only"}, (
        f"untagging the stream changed ListTagsOfResource(table ARN) to {table_tags_final!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
