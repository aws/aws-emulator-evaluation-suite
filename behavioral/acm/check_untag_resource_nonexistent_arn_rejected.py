"""untag-resource-nonexistent-arn-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-resource-nonexistent-arn-rejected"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource on a nonexistent ACME endpoint ARN raises ResourceNotFoundException, while
    the same call on a real tagged endpoint removes the tag."""
    acm = ctx.client("acm")
    account = _account_id(ctx)
    # UntagResource does not support certificate ARNs, so an ACME endpoint ARN is used.
    fake_arn = f"arn:aws:acm:{ctx.region}:{account}:acme-endpoint/{uuid.uuid4().hex}"

    code, message = _error(
        lambda: acm.untag_resource(ResourceArn=fake_arn, TagKeys=["sim2real-behav"])
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for non-existent resource ARN, got {code!r}"
    )
    expected_message = f"Could not find acme-endpoint {fake_arn}."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control: UntagResource against a real, tagged ACME endpoint actually removes it.
    endpoint_arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
    )["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=endpoint_arn))

    acm.tag_resource(ResourceArn=endpoint_arn, Tags=[{"Key": "sim2real-behav", "Value": "probe"}])
    before = {t["Key"]: t["Value"] for t in acm.list_tags_for_resource(ResourceArn=endpoint_arn)["Tags"]}
    assert before.get("sim2real-behav") == "probe", f"expected tag applied to real resource, got {before!r}"

    acm.untag_resource(ResourceArn=endpoint_arn, TagKeys=["sim2real-behav"])
    after = {t["Key"]: t["Value"] for t in acm.list_tags_for_resource(ResourceArn=endpoint_arn)["Tags"]}
    assert "sim2real-behav" not in after, f"tag was not removed: {after}"


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
