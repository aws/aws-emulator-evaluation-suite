"""untag-resource-invalid-key-validation-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-resource-invalid-key-validation-rejected"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UntagResource with an invalid tag key raises ValidationException and keeps the existing tag;
    untagging with the valid key then removes it."""
    acm = ctx.client("acm")
    # UntagResource does not support certificates, so an ACME endpoint is used.
    endpoint_arn = _create_acme_endpoint(ctx)
    _wait_for_endpoint_status(ctx, endpoint_arn, {"ACTIVE"})
    acm.tag_resource(ResourceArn=endpoint_arn, Tags=[{"Key": "sim2real", "Value": "keep"}])

    # "#" and "!" are outside the ACM tag-key character class (letters/spaces/digits/_.:/=+-@)
    bad_key = "bad#key!"
    code, message = _error(lambda: acm.untag_resource(ResourceArn=endpoint_arn, TagKeys=[bad_key]))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        "1 validation error detected: Value of the input at 'tagKeys' failed to satisfy constraint: "
        "Member must satisfy constraint: [Member must have length less than or equal to 128, "
        "Member must have length greater than or equal to 1, Member must satisfy regular expression "
        "pattern: ([\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]*), Member must not be null]"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the original tag survives the rejected untag attempt
    tags = acm.list_tags_for_resource(ResourceArn=endpoint_arn)["Tags"]
    assert {"Key": "sim2real", "Value": "keep"} in tags, (
        f"expected tag sim2real=keep to survive the rejected untag, got {tags!r}"
    )

    # positive control: untagging with the real, valid key succeeds
    acm.untag_resource(ResourceArn=endpoint_arn, TagKeys=["sim2real"])
    tags_after = acm.list_tags_for_resource(ResourceArn=endpoint_arn)["Tags"]
    assert {"Key": "sim2real", "Value": "keep"} not in tags_after, (
        f"expected tag sim2real=keep to be removed by the valid-key untag, got {tags_after!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_acme_endpoint(ctx):
    acm = ctx.client("acm")
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _delete_acme_endpoint(ctx, arn))
    return arn


def _delete_acme_endpoint(ctx, arn):
    acm = ctx.client("acm")
    acm.delete_acme_endpoint(AcmeEndpointArn=arn)


def _wait_for_endpoint_status(ctx, arn, target_statuses, timeout_s=90.0, interval_s=3.0):
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        if last in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"endpoint {arn} never reached {target_statuses}, last status {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

