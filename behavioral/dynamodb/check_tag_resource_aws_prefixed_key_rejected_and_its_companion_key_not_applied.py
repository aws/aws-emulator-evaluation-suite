"""tag-resource-aws-prefixed-key-rejected-and-its-companion-key-not-applied."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-aws-prefixed-key-rejected-and-its-companion-key-not-applied"
GROUP = "tagging"
SERVICES = ["dynamodb"]

_EXPECTED_CODE = "ValidationException"
_RESERVED_KEY = "aws:owner"
_EXPECTED_MESSAGE = f"Tag Key cannot be prefixed with aws:, Key: {_RESERVED_KEY}"


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


def _tag(ctx, ddb, arn: str, pairs: list) -> None:
    """TagResource, retried while DynamoDB rate-limits tagging on the account."""
    deadline = time.monotonic() + _budget_s(ctx, 60.0)
    while True:
        try:
            ddb.tag_resource(ResourceArn=arn, Tags=pairs)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "LimitExceededException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _refusal(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn() raises; a success raises, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it returned {result!r}")


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource carrying an aws:-prefixed key beside a valid one is refused and applies neither,
    so a later tag lists without them; the valid key sent alone then merges into the tags.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Tagging.html
    """
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-tpx-")
    arn = ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )["TableDescription"]["TableArn"]
    ctx.on_cleanup(_delete_table(ddb, name))
    _wait_active(ctx, ddb, name)

    held = {"team": "blue"}
    _tag(ctx, ddb, arn, [{"Key": "team", "Value": "blue"}])
    got = _settled(ctx, ddb, arn, held, "ListTagsOfResource showed the first tag")
    assert got == held, f"after tagging team the table lists {got!r}, expected {held!r}"

    mixed = [{"Key": _RESERVED_KEY, "Value": "lab"}, {"Key": "stage", "Value": "test"}]
    got = _refusal(lambda: _tag(ctx, ddb, arn, mixed))
    assert got == (_EXPECTED_CODE, _EXPECTED_MESSAGE), (
        f"an aws:-prefixed key beside stage gave {got!r}, expected {(_EXPECTED_CODE, _EXPECTED_MESSAGE)!r}"
    )

    # The control is ordered after the refusal: once its tag is listed, a stage tag from the
    # refused call would be listed too.
    _tag(ctx, ddb, arn, [{"Key": "cost", "Value": "lab"}])
    want = {**held, "cost": "lab"}
    got = _settled(ctx, ddb, arn, want, "ListTagsOfResource showed the control tag")
    assert got == want, f"after the refused call and the control tag the table lists {got!r}, expected {want!r}"

    _tag(ctx, ddb, arn, [{"Key": "stage", "Value": "test"}])
    final = {**want, "stage": "test"}
    got = _settled(ctx, ddb, arn, final, "ListTagsOfResource showed the stage tag sent alone")
    assert got == final, f"the stage tag sent alone left the table listing {got!r}, expected {final!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
