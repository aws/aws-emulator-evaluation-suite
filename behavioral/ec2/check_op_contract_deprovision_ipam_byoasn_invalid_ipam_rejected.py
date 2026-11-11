"""op-contract-deprovision-ipam-byoasn-invalid-ipam-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-deprovision-ipam-byoasn-invalid-ipam-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """DeprovisionIpamByoasn with a nonexistent IPAM ID fails with InvalidIpamId.NotFound, and with a
    real IPAM but an ASN never provisioned to it fails with InvalidAsn.NotFound, each with its exact
    message."""
    ec2 = ctx.client("ec2")

    # error boundary #1: IpamId does not exist at all
    bogus_ipam_id = "ipam-00000000000000000"
    error = _error(lambda: ec2.deprovision_ipam_byoasn(IpamId=bogus_ipam_id, Asn="64512"))
    assert error["Code"] == "InvalidIpamId.NotFound", error
    assert error.get("Message") == f"The ipam ID '{bogus_ipam_id}' does not exist", error

    # Error boundary #2: a real IPAM to which the ASN was never provisioned. The per-Region IPAM quota
    # can be 1, so reuse an existing IPAM before creating one (ResourceLimitExceeded otherwise).
    existing_ipams = ec2.describe_ipams()["Ipams"]
    if existing_ipams:
        ipam_id = existing_ipams[0]["IpamId"]
    else:
        ipam = ec2.create_ipam(
            Description=ctx.unique_name("sim2real-behav-ipam-"),
            TagSpecifications=[
                {
                    "ResourceType": "ipam",
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-ipam-")}],
                }
            ],
        )["Ipam"]
        ipam_id = ipam["IpamId"]
        ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))

    error2 = _error(lambda: ec2.deprovision_ipam_byoasn(IpamId=ipam_id, Asn="64512"))
    assert error2["Code"] == "InvalidAsn.NotFound", error2
    assert error2.get("Message") == "The requested ASN could not be found.", error2


def _error(fn):
    """Call fn() and return its botocore Error dict; a call that succeeds raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
