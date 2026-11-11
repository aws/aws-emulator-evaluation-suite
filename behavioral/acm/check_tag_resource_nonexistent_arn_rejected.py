"""tag-resource-nonexistent-arn-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-nonexistent-arn-rejected"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource on a nonexistent ACME endpoint ARN is refused with ResourceNotFoundException and
    the exact message, while the same call on a real ACME endpoint applies the tag."""
    acm = ctx.client("acm")
    account = _account_id(ctx)
    fake_arn = f"arn:aws:acm:{ctx.region}:{account}:acme-endpoint/{uuid.uuid4().hex}"

    code, message = _client_error(
        lambda: acm.tag_resource(
            ResourceArn=fake_arn, Tags=[{"Key": "sim2real-behav", "Value": "probe"}]
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for non-existent resource ARN, got {code!r}"
    )
    expected = f"Could not find acme-endpoint {fake_arn}."
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # Positive control: TagResource against a real ACME endpoint succeeds and the tag is
    # visible via ListTagsForResource.
    endpoint_arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
    )["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=endpoint_arn))

    acm.tag_resource(ResourceArn=endpoint_arn, Tags=[{"Key": "sim2real-behav", "Value": "probe"}])
    tags = {t["Key"]: t["Value"] for t in acm.list_tags_for_resource(ResourceArn=endpoint_arn)["Tags"]}
    assert tags.get("sim2real-behav") == "probe", f"tag not applied to real resource: {tags}"


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _client_error(fn):
    """Return (code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a refusal, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
