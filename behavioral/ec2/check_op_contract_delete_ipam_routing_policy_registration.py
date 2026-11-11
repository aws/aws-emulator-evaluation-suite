"""op-contract-delete-ipam-routing-policy-registration."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-delete-ipam-routing-policy-registration"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."

_PLACEHOLDER_ASSOCIATION_ID = "ipam-internet-registry-assoc-0aaaaaaaaaaaaaaaa"
_PLACEHOLDER_CIDR = "198.51.100.0/24"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteIpamRoutingPolicyRegistration on a nonexistent association and CIDR answers DryRun with
    DryRunOperation and the real call with InvalidIpamInternetRegistryAssociationId.NotFound, each
    with its exact message."""
    ec2 = ctx.client("ec2")

    if not hasattr(ec2, "delete_ipam_routing_policy_registration"):
        raise AssertionError(
            "unreachable: installed boto3 does not expose "
            "DeleteIpamRoutingPolicyRegistration (too new for this SDK version)"
        )

    dry_run_code, dry_run_message = _error(
        lambda: ec2.delete_ipam_routing_policy_registration(
            IpamInternetRegistryAssociationId=_PLACEHOLDER_ASSOCIATION_ID,
            Cidr=_PLACEHOLDER_CIDR,
            DryRun=True,
        )
    )
    assert dry_run_code == "DryRunOperation", f"expected DryRunOperation, got {dry_run_code!r}"
    assert dry_run_message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message {dry_run_message!r}"

    real_code, real_message = _error(
        lambda: ec2.delete_ipam_routing_policy_registration(
            IpamInternetRegistryAssociationId=_PLACEHOLDER_ASSOCIATION_ID,
            Cidr=_PLACEHOLDER_CIDR,
        )
    )
    assert real_code == "InvalidIpamInternetRegistryAssociationId.NotFound", f"unexpected code {real_code!r}"
    assert real_message == f"The ipam-internet-registry-association ID '{_PLACEHOLDER_ASSOCIATION_ID}' does not exist", f"unexpected message {real_message!r}"


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a call that
    succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
