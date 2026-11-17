"""tag-resource-second-call-adds-keys-and-retagging-replaces-the-value."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-second-call-adds-keys-and-retagging-replaces-the-value"
GROUP = "tagging"
SERVICES = ["dynamodb"]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_active(ctx, ddb, name: str) -> None:
    """DescribeTable polled until the table is ACTIVE."""
    deadline = time.monotonic() + _budget_s(ctx, 240.0)
    while True:
        status = ddb.describe_table(TableName=name)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"the run budget ended before table {name} became ACTIVE")
            raise AssertionError(f"table {name} is still {status!r}, not ACTIVE")
        time.sleep(2)


def _delete_table(ddb, name: str):
    """A cleanup deleting the table; a table still being created is retried until it can be deleted."""

    def run_undo():
        deadline = time.monotonic() + 240.0
        while True:
            try:
                ddb.delete_table(TableName=name)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code != "ResourceInUseException" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    return run_undo


def _tag(ctx, ddb, arn: str, pairs: dict) -> None:
    """TagResource, retried while DynamoDB rate-limits tagging on the account."""
    deadline = time.monotonic() + _budget_s(ctx, 60.0)
    while True:
        try:
            ddb.tag_resource(ResourceArn=arn, Tags=[{"Key": k, "Value": v} for k, v in pairs.items()])
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "LimitExceededException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _listed(ddb, arn: str) -> dict:
    """The table's tags across every ListTagsOfResource page."""
    out: dict = {}
    kwargs = {"ResourceArn": arn}
    while True:
        resp = ddb.list_tags_of_resource(**kwargs)
        out.update({t["Key"]: t["Value"] for t in resp.get("Tags", [])})
        if not resp.get("NextToken"):
            return out
        kwargs["NextToken"] = resp["NextToken"]


def _settled(ctx, ddb, arn: str, want: dict, what: str) -> dict:
    """The tag map polled until it equals want or the wait ends; tagging is eventually consistent."""
    deadline = time.monotonic() + _budget_s(ctx, 60.0)
    while True:
        got = _listed(ddb, arn)
        if got == want:
            return got
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"the run budget ended before {what}")
            return got
        time.sleep(2)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second TagResource adds its key beside the keys already set, and re-tagging a present key
    replaces its value; ListTagsOfResource settles on exactly the merged map each time.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Tagging.html
    """
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-trk-")
    arn = ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )["TableDescription"]["TableArn"]
    ctx.on_cleanup(_delete_table(ddb, name))
    _wait_active(ctx, ddb, name)

    first = {"team": "blue", "stage": "test"}
    _tag(ctx, ddb, arn, first)
    got = _settled(ctx, ddb, arn, first, "ListTagsOfResource showed the first two tags")
    assert got == first, f"after tagging team and stage the table lists {got!r}, expected {first!r}"

    _tag(ctx, ddb, arn, {"cost": "lab"})
    merged = {**first, "cost": "lab"}
    got = _settled(ctx, ddb, arn, merged, "ListTagsOfResource showed the merged tags")
    assert got == merged, f"a second TagResource left the table listing {got!r}, expected {merged!r}"

    _tag(ctx, ddb, arn, {"team": "green"})
    replaced = {**merged, "team": "green"}
    got = _settled(ctx, ddb, arn, replaced, "ListTagsOfResource showed the replaced value")
    assert got == replaced, f"re-tagging team left the table listing {got!r}, expected {replaced!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
