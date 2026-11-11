"""tag-resource-exceeds-tag-limit-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "tag-resource-exceeds-tag-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A single TagResource call with 51 tags (Tags max-list-length is 50) is rejected wholesale with
    ValidationException and applies none of them.
    """
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-ddb-")
    created = ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, table_name))
    table_arn = created["TableDescription"]["TableArn"]
    _wait_table_active(ddb, table_name)

    def _list_tags():
        return ddb.list_tags_of_resource(ResourceArn=table_arn).get("Tags", [])

    # ListTagsOfResource is eventually consistent with TagResource, so the
    # confirming read is a bounded poll, not a single point-in-time read.
    control_tag = {"Key": "sim2real-control", "Value": "v"}
    ddb.tag_resource(ResourceArn=table_arn, Tags=[control_tag])
    control_tags = _poll_until(
        _list_tags,
        lambda t: t == [control_tag],
        timeout_s=30.0,
        description="control tag visible via ListTagsOfResource",
    )
    assert control_tags == [control_tag], (
        f"expected the control tag to attach, found {control_tags!r}"
    )

    # A single call is used because a cumulative 51st tag is enforced only after quota
    # accounting propagates, with no bounded convergence.
    over_limit_tags = [{"Key": f"sim2real-k{i}", "Value": f"v{i}"} for i in range(51)]
    code, message = _error(lambda: ddb.tag_resource(ResourceArn=table_arn, Tags=over_limit_tags))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = "Number of Tags exceed the current limit for the provided ResourceArn"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    tags = _list_tags()
    assert tags == [control_tag], (
        f"expected only the control tag to survive the rejected request, found {tags!r}"
    )


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _error(fn):
    """(code, message) of the ClientError fn() raises; RAISES if the call unexpectedly succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _wait_table_active(ddb, table_name, timeout_s=120.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table_name)["Table"]
        if desc["TableStatus"] == "ACTIVE":
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} never became ACTIVE")


def _safe_delete_table(ddb, table_name, timeout_s=60.0, interval_s=3.0):
    """DeleteTable, retried while a just-applied TagResource still holds the table in use."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.delete_table(TableName=table_name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
