"""create-feed-malformed-access-role-arn-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-feed-malformed-access-role-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["elementalinference"]


def _subtitling_output(name: str, language: str = "eng") -> dict:
    return {"name": name, "outputConfig": {"subtitling": {"language": language}}, "status": "ENABLED"}


def _error_code(fn, on_unexpected_success=None):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    if on_unexpected_success is not None:
        on_unexpected_success(result)
    raise AssertionError(
        f"expected CreateFeed to reject the malformed accessRoleArn, but it SUCCEEDED and "
        f"returned {result!r}"
    )


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFeed with an accessRoleArn that is not an IAM role ARN of the caller's account fails with
    AccessDeniedException "Cross-account pass role is not allowed." and creates no feed, while a valid feed creates."""
    ei = ctx.client("elementalinference")
    name = ctx.unique_name("sim2real-ei-feed-")

    code, message = _error_code(
        lambda: ei.create_feed(
            name=name,
            outputs=[_subtitling_output("sub1")],
            accessRoleArn="arn:aws:iam::123456789012:notarole",
        ),
        on_unexpected_success=lambda result: ctx.on_cleanup(
            lambda: ei.delete_feed(id=result["id"])
        ),
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    assert message == "Cross-account pass role is not allowed.", message

    # Effect absent: no feed with this name was created.
    token = None
    found = False
    for _ in range(50):
        kwargs = {"maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        page = ei.list_feeds(**kwargs)
        if any(f["name"] == name for f in page["feeds"]):
            found = True
            break
        token = page.get("nextToken")
        if not token:
            break
    assert not found, "rejected feed was created anyway"

    # Positive control: the same feed without a malformed accessRoleArn is created successfully.
    control_id = ei.create_feed(name=name, outputs=[_subtitling_output("sub1")])["id"]
    ctx.on_cleanup(lambda: ei.delete_feed(id=control_id))
    control = _poll_until(lambda: ei.get_feed(id=control_id), lambda r: r["status"] == "AVAILABLE")
    assert control["status"] == "AVAILABLE", (
        f"positive control feed {control_id!r} never reached AVAILABLE: {control['status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

