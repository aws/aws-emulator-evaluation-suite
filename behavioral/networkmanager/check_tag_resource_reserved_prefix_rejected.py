"""tag-resource-reserved-prefix-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-reserved-prefix-rejected"
GROUP = "overly-permissive"
SERVICES = ["networkmanager"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource rejects a reserved 'aws:' key prefix, but a normal tag key is applied."""
    nm = ctx.client("networkmanager")
    gn_id, gn_arn = _create_global_network(ctx, nm)

    # Positive control: a normal tag key/value is applied and visible. This must run before the
    # break below — a global network with zero tags makes ListTagsForResource raise
    # ResourceNotFoundException rather than return an empty TagList, so the first successful tag
    # is also what makes the resource readable at all.
    nm.tag_resource(ResourceArn=gn_arn, Tags=[{"Key": "sim2real-env", "Value": "test"}])
    tags_after_control = {t["Key"]: t["Value"] for t in nm.list_tags_for_resource(ResourceArn=gn_arn)["TagList"]}
    assert tags_after_control.get("sim2real-env") == "test"

    # Break: the "aws:" prefix is reserved and must be rejected.
    code, message = _error_code(
        lambda: nm.tag_resource(ResourceArn=gn_arn, Tags=[{"Key": "aws:reserved", "Value": "x"}])
    )
    assert code == "ValidationException", f"actual code: {code!r}"
    expected_message = "Tag cannot start with aws:"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the reserved tag was not applied, and the earlier control tag is untouched.
    tags_after_break = {t["Key"]: t["Value"] for t in nm.list_tags_for_resource(ResourceArn=gn_arn)["TagList"]}
    assert "aws:reserved" not in tags_after_break
    assert tags_after_break.get("sim2real-env") == "test"


def _safe_call(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _is_gone(fn):
    """True once fn() is refused with ResourceNotFoundException or answers an empty list (polling only)."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"] == "ResourceNotFoundException"
    return result == []


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_global_network(ctx, nm):
    gn = nm.create_global_network(Description=ctx.unique_name("sim2real-gn-"))["GlobalNetwork"]
    gn_id = gn["GlobalNetworkId"]
    gn_arn = gn["GlobalNetworkArn"]
    ctx.on_cleanup(lambda: _delete_global_network_and_wait(nm, gn_id))
    _poll_until(
        lambda: nm.describe_global_networks(GlobalNetworkIds=[gn_id])["GlobalNetworks"][0]["State"],
        lambda s: s == "AVAILABLE",
    )
    return gn_id, gn_arn


def _delete_global_network_and_wait(nm, gn_id):
    _safe_call(lambda: nm.delete_global_network(GlobalNetworkId=gn_id))
    _poll_until(
        lambda: _is_gone(lambda: nm.describe_global_networks(GlobalNetworkIds=[gn_id])["GlobalNetworks"]),
        lambda gone: gone,
        timeout_s=150.0,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
