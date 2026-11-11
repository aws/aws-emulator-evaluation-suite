"""op-contract-associate-ipam-byoasn."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-associate-ipam-byoasn"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateIpamByoasn with DryRun fails DryRunOperation, and for an ASN and CIDR never
    provisioned fails InvalidCidr.NotFound with "The requested CIDR could not be found in IPAM.".
    """
    ec2 = ctx.client("ec2")
    # Documentation/example ranges (RFC 5398 / RFC 5737) so nothing here resembles a real ASN
    # or a real customer CIDR.
    asn = "64500"
    cidr = "203.0.113.0/24"

    dry_run_code, dry_run_message = _client_error(
        lambda: ec2.associate_ipam_byoasn(Asn=asn, Cidr=cidr, DryRun=True)
    )
    assert dry_run_code == "DryRunOperation", f"unexpected dry-run code: {dry_run_code}"
    assert dry_run_message == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected dry-run message: {dry_run_message!r}"
    )

    code, message = _client_error(lambda: ec2.associate_ipam_byoasn(Asn=asn, Cidr=cidr))
    assert code == "InvalidCidr.NotFound", f"unexpected error code: {code}"
    assert message == "The requested CIDR could not be found in IPAM.", (
        f"unexpected error message: {message!r}"
    )


def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because a target
    ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
