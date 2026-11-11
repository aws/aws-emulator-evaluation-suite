"""tag-resource-exceeds-tag-limit-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-resource-exceeds-tag-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["internetmonitor"]


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected success raises, so a
    target that accepts what AWS refuses is never read as a code mismatch."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it succeeded and returned {result!r}")


def _safe_delete_monitor(im, name, timeout_s=50.0):
    """DeleteMonitor requires the monitor be INACTIVE first; transition it, then delete.

    UpdateMonitor refuses a PENDING monitor, so the transition is retried to the deadline.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            im.update_monitor(MonitorName=name, Status="INACTIVE")
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            if time.monotonic() >= deadline:
                raise
            time.sleep(2.0)
    while time.monotonic() < deadline:
        try:
            status = im.get_monitor(MonitorName=name)["Status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        if status == "INACTIVE":
            break
        time.sleep(2.0)
    im.delete_monitor(MonitorName=name)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource with more than 200 tag entries (the documented TagMap limit) is rejected with
    BadRequestException, leaves the resource's tags untouched, while tagging with a small, valid tag
    set on the same resource still succeeds (positive control)."""
    im = ctx.client("internetmonitor")
    name = ctx.unique_name("sim2real-im-tagover-")
    created = im.create_monitor(MonitorName=name, TrafficPercentageToMonitor=100)
    arn = created["Arn"]
    ctx.on_cleanup(lambda: _safe_delete_monitor(im, name))

    too_many_tags = {f"key-{i}": f"value-{i}" for i in range(201)}
    code, message = _error(lambda: im.tag_resource(ResourceArn=arn, Tags=too_many_tags))
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    assert message == "Invalid request body", f"unexpected message: {message!r}"

    tags_after = im.list_tags_for_resource(ResourceArn=arn).get("Tags", {})
    assert "key-0" not in tags_after, f"rejected tag set leaked into resource: {tags_after!r}"
    assert tags_after == {}, f"expected no tags after rejected TagResource, got {tags_after!r}"

    im.tag_resource(ResourceArn=arn, Tags={"team": "sim2real"})
    tags_final = im.list_tags_for_resource(ResourceArn=arn).get("Tags", {})
    assert tags_final.get("team") == "sim2real", (
        f"expected valid TagResource to succeed and be visible, got {tags_final!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
