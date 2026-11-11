"""untag-resource-removes-tag."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource-removes-tag"
GROUP = "state-machine"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RemoveTagsFromCertificate removes exactly the named tag: ListTagsForCertificate lists both
    added tags before and only the kept one after."""
    acm = ctx.client("acm")
    domain = f"{ctx.unique_name('sim2real-acm-utag')}.example.com"
    cert_arn = acm.request_certificate(DomainName=domain, ValidationMethod="DNS")["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=cert_arn))

    acm.add_tags_to_certificate(
        CertificateArn=cert_arn,
        Tags=[
            {"Key": "KeepMe", "Value": "yes"},
            {"Key": "DropMe", "Value": "temp"},
        ],
    )
    before = {t["Key"]: t["Value"] for t in acm.list_tags_for_certificate(CertificateArn=cert_arn)["Tags"]}
    assert before == {"KeepMe": "yes", "DropMe": "temp"}, f"unexpected tags before untag: {before}"

    acm.remove_tags_from_certificate(CertificateArn=cert_arn, Tags=[{"Key": "DropMe", "Value": "temp"}])

    after = {t["Key"]: t["Value"] for t in acm.list_tags_for_certificate(CertificateArn=cert_arn)["Tags"]}
    assert after == {"KeepMe": "yes"}, f"expected only KeepMe to remain, got {after}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
