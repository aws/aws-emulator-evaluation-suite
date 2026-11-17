"""untag-resource-of-fresh-keys-restores-the-table-tags-listed-before."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-resource-of-fresh-keys-restores-the-table-tags-listed-before"
GROUP = "tagging"
SERVICES = ["dynamodb"]

_PAGE_CAP = 200  # a walk whose token never ends fails instead of spinning

_KEY = {
    "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
    "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
}


def _wait_cap(ctx, cap_s: float) -> float:
    """cap_s, shortened when the runner stops the check sooner, keeping 5 s for the failure."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _drop_table(ddb, name: str):
    """A cleanup deleting the table, backing off while a create or tag update holds it; a failure raises."""

    def status() -> str:
        try:
            return ddb.describe_table(TableName=name)["Table"]["TableStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return "GONE"

    def undo() -> None:
        for attempt in range(8):
            # A table just created can still read not-found, so GONE still sends the delete.
            if status() == "DELETING":
                return
            try:
                ddb.delete_table(TableName=name)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code != "ResourceInUseException" or attempt == 7:
                    raise
            time.sleep(min(3 * 2 ** attempt, 60))

    return undo


def _new_table(ctx, ddb, name: str, **params) -> dict:
    """CreateTable, its delete registered at once, then DescribeTable polled to ACTIVE."""
    ddb.create_table(TableName=name, **params)
    ctx.on_cleanup(_drop_table(ddb, name))
    deadline = time.monotonic() + _wait_cap(ctx, 240.0)
    while True:
        try:
            table = ddb.describe_table(TableName=name)["Table"]
        except ClientError as exc:
            # DescribeTable can read not-found for a moment after CreateTable.
            if exc.response["Error"]["Code"] != "ResourceNotFoundException" or time.monotonic() >= deadline:
                raise
            table = {"TableStatus": "CREATING"}
        if table["TableStatus"] == "ACTIVE" or time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert table["TableStatus"] == "ACTIVE", f"table {name} settled at {table['TableStatus']!r}"
    return table


def _rate_limited(ctx, call) -> None:
    """call(), repeated while DynamoDB answers LimitExceededException for tagging on the account."""
    deadline = time.monotonic() + _wait_cap(ctx, 60.0)
    for attempt in range(10):
        try:
            call()
            return
        except ClientError as exc:
            last = attempt == 9 or time.monotonic() >= deadline
            if exc.response["Error"]["Code"] != "LimitExceededException" or last:
                raise
        time.sleep(min(2 ** attempt, 16))


def _tag_map(ddb, arn: str) -> dict:
    """The table's tags over every ListTagsOfResource page."""
    found, kwargs = {}, {"ResourceArn": arn}
    for _ in range(_PAGE_CAP):
        page = ddb.list_tags_of_resource(**kwargs)
        found.update({t["Key"]: t["Value"] for t in page.get("Tags", [])})
        if not page.get("NextToken"):
            return found
        kwargs["NextToken"] = page["NextToken"]
    raise AssertionError(f"ListTagsOfResource still returned a NextToken after {_PAGE_CAP} pages")


def _tags_until(ctx, ddb, arn: str, want: dict) -> dict:
    """The tag map read until it equals want or the wait runs out; tag writes settle after the call."""
    deadline = time.monotonic() + _wait_cap(ctx, 60.0)
    while True:
        got = _tag_map(ddb, arn)
        if got == want or time.monotonic() >= deadline:
            return got
        time.sleep(2)


def _pairs(mapping: dict) -> list:
    return [{"Key": k, "Value": v} for k, v in mapping.items()]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource of two keys the table did not carry, then UntagResource of those keys, settles
    ListTagsOfResource on exactly the tags it listed before, creation tags included.
    """
    ddb = ctx.client("dynamodb")
    created = {"sim2real": CHECK, "owner": "lab"}
    table = _new_table(ctx, ddb, ctx.unique_name("sim2real-dtuf-"), BillingMode="PAY_PER_REQUEST",
                       Tags=_pairs(created), **_KEY)
    arn = table["TableArn"]

    before = _tags_until(ctx, ddb, arn, created)
    assert before == created, f"a table created with tags {created!r} lists {before!r}"

    fresh = {"extra-a": "one", "extra-b": "two"}
    _rate_limited(ctx, lambda: ddb.tag_resource(ResourceArn=arn, Tags=_pairs(fresh)))
    tagged = {**before, **fresh}
    got = _tags_until(ctx, ddb, arn, tagged)
    assert got == tagged, f"after tagging {sorted(fresh)!r} the table lists {got!r}, expected {tagged!r}"

    _rate_limited(ctx, lambda: ddb.untag_resource(ResourceArn=arn, TagKeys=sorted(fresh)))
    got = _tags_until(ctx, ddb, arn, before)
    assert got == before, f"untagging {sorted(fresh)!r} left {got!r}, expected the earlier set {before!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
