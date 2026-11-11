"""op-contract-delete-local-gateway-virtual-interface."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-delete-local-gateway-virtual-interface"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteLocalGatewayVirtualInterface on a never-created ID answers DryRun with DryRunOperation and
    the real call with InvalidLocalGatewayVirtualInterfaceID.NotFound (exact messages); the ID still
    describes as absent, and DescribeLocalGatewayVirtualInterfaces answers with its list."""
    ec2 = ctx.client("ec2")
    fake_id = "lgw-vif-00000000000000000"

    # positive control: the credentials are healthy for this service and this
    # resource family, so a downstream rejection below is a real not-found, not blanket denial.
    resp = ec2.describe_local_gateway_virtual_interfaces()
    assert "LocalGatewayVirtualInterfaces" in resp, f"missing key: {sorted(resp)}"

    # error boundary #1: DryRun short-circuits on the permission check before EC2 ever
    # validates that the id refers to a real interface.
    dry_code, dry_message = _error(
        lambda: ec2.delete_local_gateway_virtual_interface(
            LocalGatewayVirtualInterfaceId=fake_id, DryRun=True
        )
    )
    assert dry_code == "DryRunOperation", f"expected DryRunOperation, got {dry_code}"
    assert dry_message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message {dry_message!r}"

    # error boundary #2: the real (non-DryRun) delete rejects the never-created id with the
    # specific not-found code rather than accepting it or mutating anything.
    code, message = _error(
        lambda: ec2.delete_local_gateway_virtual_interface(
            LocalGatewayVirtualInterfaceId=fake_id
        )
    )
    assert code == "InvalidLocalGatewayVirtualInterfaceID.NotFound", f"unexpected code {code}"
    assert message == f"The local-gateway-virtual-interface ID '{fake_id}' does not exist", f"unexpected message {message!r}"

    # effect-absent, via an independent read: the id still does not exist.
    still_absent = ec2.describe_local_gateway_virtual_interfaces(
        LocalGatewayVirtualInterfaceIds=[fake_id]
    )["LocalGatewayVirtualInterfaces"]
    assert still_absent == [], f"expected no interface for a never-created id, got {still_absent}"


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
