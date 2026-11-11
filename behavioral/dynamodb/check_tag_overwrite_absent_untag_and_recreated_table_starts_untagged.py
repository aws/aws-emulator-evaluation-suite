"""tag-overwrite-absent-untag-and-recreated-table-starts-untagged."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-overwrite-absent-untag-and-recreated-table-starts-untagged"
GROUP = "tables"
SERVICES = ["dynamodb"]


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


def _deadline(ctx):
    return time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)


def _tag_call(ctx, fn):
    """fn(), retried every 2 s while tagging is rate limited."""
    deadline = _deadline(ctx)
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "LimitExceededException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _tags(ddb, arn):
    out, token = {}, None
    while True:
        kwargs = {"ResourceArn": arn}
        if token:
            kwargs["NextToken"] = token
        resp = ddb.list_tags_of_resource(**kwargs)
        out.update({t["Key"]: t["Value"] for t in resp.get("Tags", [])})
        token = resp.get("NextToken")
        if not token:
            return out


def _tags_until(ctx, ddb, arn, want):
    deadline = _deadline(ctx)
    while True:
        got = _tags(ddb, arn)
        if got == want or time.monotonic() >= deadline:
            return got
        time.sleep(2)


def _create(ddb, ctx, table):
    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )
    return _wait_active(ddb, ctx, table)["TableArn"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource on an existing key replaces its value, UntagResource of an absent key succeeds and
    changes nothing, and a table re-created under the same name and ARN carries none of the old tags.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Tagging.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-tags-")
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    arn = _create(ddb, ctx, table)

    _tag_call(ctx, lambda: ddb.tag_resource(ResourceArn=arn, Tags=[{"Key": "env", "Value": "one"}, {"Key": "team", "Value": "a"}]))
    got = _tags_until(ctx, ddb, arn, {"env": "one", "team": "a"})
    assert got == {"env": "one", "team": "a"}, f"after the first TagResource the table carries {got!r}"
    _tag_call(ctx, lambda: ddb.tag_resource(ResourceArn=arn, Tags=[{"Key": "env", "Value": "two"}]))
    got = _tags_until(ctx, ddb, arn, {"env": "two", "team": "a"})
    assert got == {"env": "two", "team": "a"}, f"re-tagging 'env' left the table carrying {got!r}"

    _tag_call(ctx, lambda: ddb.untag_resource(ResourceArn=arn, TagKeys=["absent"]))
    got = _tags_until(ctx, ddb, arn, {"env": "two", "team": "a"})
    assert got == {"env": "two", "team": "a"}, f"untagging an absent key left the table carrying {got!r}"
    _tag_call(ctx, lambda: ddb.untag_resource(ResourceArn=arn, TagKeys=["team"]))
    got = _tags_until(ctx, ddb, arn, {"env": "two"})
    assert got == {"env": "two"}, f"untagging an absent key and 'team' left the table carrying {got!r}"

    ddb.delete_table(TableName=table)
    deadline = _deadline(ctx)
    while time.monotonic() < deadline:
        try:
            ddb.describe_table(TableName=table)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            break
        time.sleep(2)
    else:
        raise AssertionError(f"table {table} still describes after DeleteTable")

    again = _create(ddb, ctx, table)
    assert again == arn, f"the re-created table has ARN {again!r}, expected {arn!r}"
    _tag_call(ctx, lambda: ddb.tag_resource(ResourceArn=again, Tags=[{"Key": "fresh", "Value": "yes"}]))
    got = _tags_until(ctx, ddb, again, {"fresh": "yes"})
    assert got == {"fresh": "yes"}, f"the re-created table carries {got!r}; the old 'env' tag must not return"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
