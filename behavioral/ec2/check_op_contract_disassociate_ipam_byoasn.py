"""op-contract-disassociate-ipam-byoasn."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-disassociate-ipam-byoasn"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisassociateIpamByoasn with DryRun on two never-provisioned ASN and CIDR pairs answers
    DryRunOperation, and the real call fails with InvalidCidr.NotFound, each with its exact message."""
    ec2 = ctx.client("ec2")

    for asn, cidr in (("64512", "203.0.113.0/24"), ("4200000000", "198.51.100.0/24")):
        code, message = _client_error(lambda a=asn, c=cidr: ec2.disassociate_ipam_byoasn(Asn=a, Cidr=c, DryRun=True))
        assert code == "DryRunOperation", (asn, cidr, code)
        assert message == "Request would have succeeded, but DryRun flag is set.", (
            f"unexpected DryRunOperation message: {message!r}"
        )

    real_code, real_message = _client_error(lambda: ec2.disassociate_ipam_byoasn(Asn="64512", Cidr="203.0.113.0/24"))
    assert real_code == "InvalidCidr.NotFound", f"expected InvalidCidr.NotFound, got {real_code}"
    assert real_message == "The requested CIDR could not be found in IPAM.", (
        f"unexpected InvalidCidr.NotFound message: {real_message!r}"
    )


def _client_error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because a
    target ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
