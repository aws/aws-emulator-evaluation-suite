"""untag-resource-on-deleted-acme-resource-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "untag-resource-on-deleted-acme-resource-rejected"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource against an AcmeEndpoint ARN that has already been deleted
    returns ResourceNotFoundException; the same call against a live, tagged
    endpoint succeeds and actually removes the tag (positive control)."""
    acm = ctx.client("acm")
    dead_arn = _create_acme_endpoint(ctx)
    acm.delete_acme_endpoint(AcmeEndpointArn=dead_arn)
    _wait_for_endpoint_gone(ctx, dead_arn)

    code, message = _error(lambda: acm.untag_resource(ResourceArn=dead_arn, TagKeys=["foo"]))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for UntagResource on a deleted AcmeEndpoint, got {code!r}"
    )
    expected_message = f"Could not find acme-endpoint {dead_arn}."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # positive control: untagging a live, tagged endpoint works
    live_arn = _create_acme_endpoint(ctx)
    tag_key = ctx.unique_name("sim2real-untag-")
    acm.tag_resource(ResourceArn=live_arn, Tags=[{"Key": tag_key, "Value": "v"}])
    acm.untag_resource(ResourceArn=live_arn, TagKeys=[tag_key])
    tags_after = acm.list_tags_for_resource(ResourceArn=live_arn)["Tags"]
    assert all(t["Key"] != tag_key for t in tags_after), (
        f"expected tag {tag_key!r} to be removed after UntagResource on a live endpoint, still present in {tags_after}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_acme_endpoint(ctx, contact: str = "NOT_REQUIRED") -> str:
    acm = ctx.client("acm")
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact=contact,
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _delete_endpoint_ignore_errors(ctx, arn))
    status = _wait_for_endpoint_terminal(ctx, arn)
    if status != "ACTIVE":
        raise AssertionError(f"AcmeEndpoint {arn} settled in status {status}, expected ACTIVE")
    return arn


def _wait_for_endpoint_terminal(ctx, arn: str, timeout_s: float = 120.0, interval_s: float = 3.0) -> str:
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        if last in ("ACTIVE", "FAILED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"AcmeEndpoint {arn} never left a non-terminal status; last={last}")


def _wait_for_endpoint_gone(ctx, arn: str, timeout_s: float = 120.0, interval_s: float = 3.0) -> None:
    from botocore.exceptions import ClientError

    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            acm.describe_acme_endpoint(AcmeEndpointArn=arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"AcmeEndpoint {arn} still describable after {timeout_s}s")


def _delete_endpoint_ignore_errors(ctx, arn: str) -> None:
    from botocore.exceptions import ClientError

    acm = ctx.client("acm")
    acm.delete_acme_endpoint(AcmeEndpointArn=arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
