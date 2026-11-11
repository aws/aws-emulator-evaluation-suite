"""tag-resource-add-and-list."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-add-and-list"
GROUP = "state-machine"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A fresh certificate has no tags, AddTagsToCertificate makes exactly the added tags visible via
    ListTagsForCertificate, and after deletion ListTagsForCertificate is refused with
    ResourceNotFoundException and the exact message."""
    acm = ctx.client("acm")
    domain = f"{ctx.unique_name('sim2real-acm-txl')}.example.com"
    cert_arn = acm.request_certificate(DomainName=domain, ValidationMethod="DNS")["CertificateArn"]
    cleaned = {"done": False}

    def _cleanup():
        if not cleaned["done"]:
            from botocore.exceptions import ClientError

            try:
                acm.delete_certificate(CertificateArn=cert_arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise

    ctx.on_cleanup(_cleanup)

    # Freshly requested certificate should start with no tags.
    initial = acm.list_tags_for_certificate(CertificateArn=cert_arn)["Tags"]
    assert initial == [], f"expected no tags on fresh certificate, got {initial}"

    acm.add_tags_to_certificate(
        CertificateArn=cert_arn,
        Tags=[
            {"Key": "Environment", "Value": "sim2real-test"},
            {"Key": "Owner", "Value": "acm-behavioral-check"},
        ],
    )

    tag_list = acm.list_tags_for_certificate(CertificateArn=cert_arn)["Tags"]
    tag_map = {t["Key"]: t["Value"] for t in tag_list}
    assert tag_map == {
        "Environment": "sim2real-test",
        "Owner": "acm-behavioral-check",
    }, f"unexpected tag set after AddTagsToCertificate: {tag_map}"

    # Deleting the tagged certificate makes the same ListTagsForCertificate read refuse it.
    acm.delete_certificate(CertificateArn=cert_arn)
    cleaned["done"] = True
    delete_code, delete_message = _client_error(
        lambda: acm.list_tags_for_certificate(CertificateArn=cert_arn)
    )
    assert delete_code == "ResourceNotFoundException", (
        f"expected ListTagsForCertificate on a deleted certificate to fail with "
        f"ResourceNotFoundException, got {delete_code!r}"
    )
    expected_message = f"Could not find certificate {cert_arn}."
    assert delete_message == expected_message, (
        f"expected {expected_message!r}, got {delete_message!r}"
    )


def _client_error(fn):
    """Return (code, message) of the ClientError fn raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a refusal, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
