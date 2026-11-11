"""untag-resource-invalid-key-rejected."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-resource-invalid-key-rejected"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UntagResource with a tag key outside the documented pattern is refused with
    ValidationException and the exact message and leaves the existing tag in place, while
    UntagResource with that tag's valid key removes it."""
    acm = ctx.client("acm")
    endpoint_arn = _create_acme_endpoint(ctx)
    acm.tag_resource(ResourceArn=endpoint_arn, Tags=[{"Key": "env", "Value": "prod"}])

    def _untag_invalid_key():
        # "!" and "," are outside the UntagResource TagKeys pattern
        # ([\p{L}\p{Z}\p{N}_.:/=+\-@]*)
        return acm.untag_resource(ResourceArn=endpoint_arn, TagKeys=["not,a valid!key"])

    code, message = _error(_untag_invalid_key)
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_message = (
        "1 validation error detected: Value of the input at 'tagKeys' failed to satisfy constraint: "
        "Member must satisfy constraint: [Member must have length less than or equal to 128, "
        "Member must have length greater than or equal to 1, Member must satisfy regular expression "
        "pattern: ([\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]*), Member must not be null]"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the well-formed "env" tag was not touched
    tags = {
        t["Key"]: t["Value"]
        for t in acm.list_tags_for_resource(ResourceArn=endpoint_arn)["Tags"]
    }
    assert tags.get("env") == "prod", f"expected env=prod to survive the rejected untag, got {tags!r}"

    # positive control: removing the real tag with a well-formed key succeeds
    acm.untag_resource(ResourceArn=endpoint_arn, TagKeys=["env"])
    tags_after = {
        t["Key"]: t["Value"]
        for t in acm.list_tags_for_resource(ResourceArn=endpoint_arn)["Tags"]
    }
    assert "env" not in tags_after, f"expected env tag removed by valid-key untag, got {tags_after!r}"


def _error(fn) -> tuple[str, str | None]:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _wait_for_endpoint_terminal(
    ctx, arn: str, timeout_s: float = 120.0, interval_s: float = 3.0
) -> dict[str, Any]:
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        endpoint = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
        if endpoint["Status"] in ("ACTIVE", "FAILED"):
            if endpoint["Status"] != "ACTIVE":
                raise AssertionError(
                    f"endpoint entered FAILED: {endpoint.get('FailureReason')}"
                )
            return endpoint
        time.sleep(interval_s)
    raise AssertionError(f"AcmeEndpoint {arn} stayed CREATING past {timeout_s}s")


def _create_acme_endpoint(ctx) -> str:
    acm = ctx.client("acm")
    arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact="NOT_REQUIRED",
    )["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn))
    _wait_for_endpoint_terminal(ctx, arn)
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
