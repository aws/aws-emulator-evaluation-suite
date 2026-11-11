"""tag-resource-nonexistent-arn-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "tag-resource-nonexistent-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["amp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource against an AMP workspace ARN that does not exist is rejected with
    NotFoundException and creates no tag state anywhere; tagging a real workspace
    (positive control, same file) succeeds."""
    amp = ctx.client("amp")
    workspace_id = amp.create_workspace(alias=ctx.unique_name("sim2real-amp-ws-"))["workspaceId"]
    ctx.on_cleanup(lambda: amp.delete_workspace(workspaceId=workspace_id))
    _poll_until(
        lambda: amp.describe_workspace(workspaceId=workspace_id)["workspace"]["status"]["statusCode"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
    )
    real_arn = amp.describe_workspace(workspaceId=workspace_id)["workspace"]["arn"]
    bogus_arn = real_arn[:-8] + "ffffffff"
    assert bogus_arn != real_arn, f"derived bogus_arn collided with real_arn: {real_arn!r}"

    # Break exactly one thing: tag a workspace ARN that was never created.
    code, message = _error(lambda: amp.tag_resource(resourceArn=bogus_arn, tags={"sim2real-owner": "behavioral"}))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    expected = "Resource was not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the real workspace picked up no tags from the rejected call.
    real_tags = amp.list_tags_for_resource(resourceArn=real_arn)["tags"]
    assert real_tags == {}, f"expected no tags on real workspace after rejected call, got {real_tags!r}"

    # Positive control: tagging the real workspace succeeds.
    amp.tag_resource(resourceArn=real_arn, tags={"sim2real-owner": "behavioral"})
    real_tags = amp.list_tags_for_resource(resourceArn=real_arn)["tags"]
    expected = {"sim2real-owner": "behavioral"}
    assert real_tags == expected, f"expected {expected!r} after positive-control tag, got {real_tags!r}"


def _error(fn):
    """Call fn(), which must fail; return its botocore error (code, message). An unexpected
    SUCCESS raises, so a target that accepts what AWS refuses is never read as a mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
