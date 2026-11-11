"""tag-resource-generic-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-generic-lifecycle"
GROUP = "state-machine"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag added to an ACME endpoint with TagResource is listed by ListTagsForResource and removed
    by UntagResource, while ListTagsForCertificate refuses the endpoint ARN with
    InvalidArnException and the exact message: the two tagging APIs are exclusive by resource type."""
    acm = ctx.client("acm")

    endpoint_arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact="NOT_REQUIRED",
    )["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _best_effort(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=endpoint_arn)))

    # No tags yet.
    initial = acm.list_tags_for_resource(ResourceArn=endpoint_arn)["Tags"]
    assert initial == [], f"expected no tags on a fresh ACME endpoint, got {initial}"

    # The certificate-specific tagging surface explicitly rejects a non-certificate resource —
    # the two tagging APIs are exclusive by resource type, not interchangeable.
    code, message = _error(lambda: acm.list_tags_for_certificate(CertificateArn=endpoint_arn))
    assert code == "InvalidArnException", (
        f"expected ListTagsForCertificate to reject a non-certificate ARN, got {code}"
    )
    assert message == f"{endpoint_arn} is not a valid ARN", message

    acm.tag_resource(ResourceArn=endpoint_arn, Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}])

    tags_after = {t["Key"]: t["Value"] for t in acm.list_tags_for_resource(ResourceArn=endpoint_arn)["Tags"]}
    assert tags_after.get("sim2real-owner") == "behavioral-suite", (
        f"expected sim2real-owner=behavioral-suite after TagResource, got {tags_after}"
    )

    acm.untag_resource(ResourceArn=endpoint_arn, TagKeys=["sim2real-owner"])

    tags_removed = {t["Key"]: t["Value"] for t in acm.list_tags_for_resource(ResourceArn=endpoint_arn)["Tags"]}
    assert "sim2real-owner" not in tags_removed, (
        f"expected sim2real-owner removed after UntagResource, still present: {tags_removed}"
    )


def _error(fn):
    """Call fn(); return its error (code, message). A success raises: accepting a call AWS refuses is a
    mismatch of its own, not a wrong error code."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _best_effort(fn):
    fn()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

