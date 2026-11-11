"""op-contract-describe-carrier-gateways."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-carrier-gateways"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeCarrierGateways: list-shape success plus the documented
    InvalidCarrierGatewayID.NotFound boundary for a well-formed but nonexistent
    carrier gateway ID."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_carrier_gateways()
    assert "CarrierGateways" in resp, f"expected CarrierGateways key in response, got {sorted(resp)}"
    assert isinstance(resp["CarrierGateways"], list), (
        f"expected CarrierGateways to be a list, got {type(resp['CarrierGateways'])!r}"
    )

    fake_gateway_id = "cagw-" + "0" * 17
    not_found_code, not_found_code_msg = _error(
        lambda: ec2.describe_carrier_gateways(CarrierGatewayIds=[fake_gateway_id])
    )
    assert not_found_code == "InvalidCarrierGatewayID.NotFound", (
        f"expected InvalidCarrierGatewayID.NotFound, got {not_found_code}"
    )
    assert not_found_code_msg == f"The CarrierGateway ID '{fake_gateway_id}' does not exist", (
        f"expected the exact InvalidCarrierGatewayID.NotFound message, got {not_found_code_msg!r}"
    )

    dry_code, dry_code_msg = _error(lambda: ec2.describe_carrier_gateways(DryRun=True))
    assert dry_code == "DryRunOperation", f"expected DryRunOperation, got {dry_code}"
    assert dry_code_msg == "Request would have succeeded, but DryRun flag is set.", (
        f"expected the exact DryRunOperation message, got {dry_code_msg!r}"
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
