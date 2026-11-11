"""customer-gateway-and-vpn-gateway-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "customer-gateway-and-vpn-gateway-lifecycle"
GROUP = 'vpc-networking'
SERVICES = ['ec2']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCustomerGateway/CreateVpnGateway reach available and delete cleanly."""
    ec2 = ctx.client("ec2")
    cgw_resp = ec2.create_customer_gateway(
        Type="ipsec.1", IpAddress="203.0.113.12", BgpAsn=65000,
        TagSpecifications=[{"ResourceType": "customer-gateway", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )
    cgw = cgw_resp["CustomerGateway"]
    cgw_id = cgw["CustomerGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_customer_gateway(CustomerGatewayId=cgw_id))
    assert cgw["BgpAsn"] == "65000", f"expected BgpAsn 65000, got {cgw}"
    assert cgw["State"] == "available", f"expected available, got {cgw['State']}"

    vgw_resp = ec2.create_vpn_gateway(Type="ipsec.1", TagSpecifications=[{"ResourceType": "vpn-gateway", "Tags": [{"Key": "sim2real", "Value": "1"}]}])
    vgw_id = vgw_resp["VpnGateway"]["VpnGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_vpn_gateway(VpnGatewayId=vgw_id))
    assert vgw_resp["VpnGateway"]["Type"] == "ipsec.1"

    vgw_state = _poll_until(
        lambda: ec2.describe_vpn_gateways(VpnGatewayIds=[vgw_id])["VpnGateways"][0]["State"],
        lambda s: s == "available",
        timeout_s=60, interval_s=2,
    )
    assert vgw_state == "available", f"expected vpn gateway available, got {vgw_state}"

    ec2.delete_customer_gateway(CustomerGatewayId=cgw_id)

    # Empirical: DeleteCustomerGateway is idempotent — the gateway lingers in the
    # "deleted" state and a repeat delete succeeds rather than erroring.
    ec2.delete_customer_gateway(CustomerGatewayId=cgw_id)
    state = ec2.describe_customer_gateways(CustomerGatewayIds=[cgw_id])[
        "CustomerGateways"
    ][0]["State"]
    assert state == "deleted", f"expected state deleted after delete, got {state}"

    # Independent terminal read on the VPN gateway half: prove the delete this
    # check issues (not just the cleanup lambda) actually lands, via DescribeVpnGateways.
    ec2.delete_vpn_gateway(VpnGatewayId=vgw_id)
    vgw_final = _poll_until(
        lambda: ec2.describe_vpn_gateways(VpnGatewayIds=[vgw_id])["VpnGateways"][0]["State"],
        lambda s: s == "deleted",
        timeout_s=60, interval_s=2,
    )
    assert vgw_final == "deleted", f"expected vpn gateway deleted, got {vgw_final}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never satisfied, last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
