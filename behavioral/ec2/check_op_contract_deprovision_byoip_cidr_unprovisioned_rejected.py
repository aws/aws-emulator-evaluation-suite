"""op-contract-deprovision-byoip-cidr-unprovisioned-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-deprovision-byoip-cidr-unprovisioned-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeprovisionByoipCidr with DryRun answers DryRunOperation; without DryRun a never-provisioned CIDR
    fails with InvalidCidr.NotFound and a malformed CIDR with InvalidParameterValue, each with its
    exact message."""
    ec2 = ctx.client("ec2")

    never_provisioned_cidr = "203.0.113.0/24"  # TEST-NET-3, never owned/provisioned by anyone

    dry_run = _error(lambda: ec2.deprovision_byoip_cidr(Cidr=never_provisioned_cidr, DryRun=True))
    assert dry_run["Code"] == "DryRunOperation", dry_run
    assert dry_run.get("Message") == "Request would have succeeded, but DryRun flag is set.", dry_run

    # real AWS validates the CIDR against the account's BYOIP inventory and
    # reports a not-found style error rather than a generic parameter error
    error = _error(lambda: ec2.deprovision_byoip_cidr(Cidr=never_provisioned_cidr))
    assert error["Code"] == "InvalidCidr.NotFound", error
    assert error.get("Message") == f"The CIDR ({never_provisioned_cidr}) does not exist.", error

    # a malformed CIDR is a distinct validation boundary from an unknown-but-well-formed one --
    # a target that rejects both with the same code has not actually distinguished them
    malformed_cidr = "not-a-cidr"
    error2 = _error(lambda: ec2.deprovision_byoip_cidr(Cidr=malformed_cidr))
    assert error2["Code"] == "InvalidParameterValue", error2
    assert error2.get("Message") == f"The CIDR ({malformed_cidr}) is not valid.", error2


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
