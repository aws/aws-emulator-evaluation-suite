"""op-contract-batch-modify-ipam-routing-policy-registrations."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-batch-modify-ipam-routing-policy-registrations"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BatchModifyIpamRoutingPolicyRegistrations on a malformed IpamInternetRegistryAssociationId
    fails DryRunOperation with DryRun and InvalidIpamInternetRegistryAssociationId.Malformed without
    it, each with its exact message.
    """
    ec2 = ctx.client("ec2")
    kwargs = dict(
        IpamInternetRegistryAssociationId="ipam-ira-00000000000000000",
        DeltaJson="[]",
    )

    dry_run_code, dry_run_code_message = _error_code(
        lambda: ec2.batch_modify_ipam_routing_policy_registrations(DryRun=True, **kwargs)
    )
    assert dry_run_code == "DryRunOperation", f"expected DryRunOperation, got {dry_run_code}"
    expected_dry_run_code_message = "Request would have succeeded, but DryRun flag is set."
    assert dry_run_code_message == expected_dry_run_code_message, f"expected message {expected_dry_run_code_message!r}, got {dry_run_code_message!r}"

    real_code, real_code_message = _error_code(
        lambda: ec2.batch_modify_ipam_routing_policy_registrations(**kwargs)
    )
    assert real_code == "InvalidIpamInternetRegistryAssociationId.Malformed", (
        "expected BatchModifyIpamRoutingPolicyRegistrations to reject a malformed "
        f"IpamInternetRegistryAssociationId with InvalidIpamInternetRegistryAssociationId.Malformed, "
        f"got {real_code}"
    )
    expected_real_code_message = "The ipam-internet-registry-association ID 'ipam-ira-00000000000000000' is malformed"
    assert real_code_message == expected_real_code_message, f"expected message {expected_real_code_message!r}, got {real_code_message!r}"
    assert real_code != dry_run_code, (
        f"the DryRun and real calls must surface distinct error codes, both came back {real_code}"
    )


def _error_code(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except Exception as exc:
        err = getattr(exc, "response", {}).get("Error")
        if not err:
            raise
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
