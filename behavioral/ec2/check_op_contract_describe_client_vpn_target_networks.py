"""op-contract-describe-client-vpn-target-networks."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-client-vpn-target-networks"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeClientVpnTargetNetworks requires a ClientVpnEndpointId. DryRun on a
    nonexistent endpoint still returns DryRunOperation, while a real call against the
    same nonexistent endpoint is rejected with InvalidClientVpnEndpointId.NotFound."""
    ec2 = ctx.client("ec2")
    fake_endpoint_id = "cvpn-endpoint-" + "0" * 17

    dry_code, dry_code_msg = _error(
        lambda: ec2.describe_client_vpn_target_networks(
            ClientVpnEndpointId=fake_endpoint_id, DryRun=True
        )
    )
    assert dry_code == "DryRunOperation", f"expected DryRunOperation, got {dry_code}"
    assert dry_code_msg == "Request would have succeeded, but DryRun flag is set.", (
        f"expected the exact DryRunOperation message, got {dry_code_msg!r}"
    )

    not_found_code, not_found_code_msg = _error(
        lambda: ec2.describe_client_vpn_target_networks(
            ClientVpnEndpointId=fake_endpoint_id
        )
    )
    assert not_found_code == "InvalidClientVpnEndpointId.NotFound", (
        f"expected InvalidClientVpnEndpointId.NotFound, got {not_found_code}"
    )
    assert not_found_code_msg == f"Endpoint {fake_endpoint_id} does not exist", (
        f"expected the exact InvalidClientVpnEndpointId.NotFound message, got {not_found_code_msg!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
