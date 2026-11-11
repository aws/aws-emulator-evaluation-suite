"""client-vpn-and-coip-error-semantics."""
from __future__ import annotations

from botocore.exceptions import ClientError, ParamValidationError

from behavioral_harness import tags


def _probe_errors(probes):
    """Run each ``(label, call, acceptable_codes)`` probe, which must fail with an acceptable code.

    Every mismatch is collected rather than raising on the first; returns the list of problems.
    """
    problems = []
    for label, call, expected in probes:
        try:
            call()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in expected:
                problems.append(f"{label}: expected {sorted(expected)}, got {code}")
        except ParamValidationError as exc:
            problems.append(f"{label}: PARAM VALIDATION: {exc}")
        else:
            problems.append(f"{label}: expected {sorted(expected)} but the call SUCCEEDED")
    return problems


# Well-formed but nonexistent resource ids (17 hex chars after the prefix), so
# probes exercise NotFound semantics rather than id-format rejection.
_ABSENT = {
    "cvpn": "cvpn-endpoint-0123456789abcdef0",
    "subnet": "subnet-0123456789abcdef0",
    "lgw_rtb": "lgw-rtb-0123456789abcdef0",
    "coip_pool": "ipv4pool-coip-0123456789abcdef0",
}

CHECK = "client-vpn-and-coip-error-semantics"
GROUP = 'error-semantics'
SERVICES = ['ec2']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateClientVpnRoute, DeleteClientVpnEndpoint and DeleteClientVpnRoute on an unknown endpoint answer
    InvalidClientVpnEndpointId.NotFound, and CreateCoipPool, CreateCoipCidr, DeleteCoipPool and DeleteCoipCidr
    on unknown ids answer their not-found code (DeleteCoipPool: InvalidParameterValue)."""
    ec2 = ctx.client("ec2")
    a = _ABSENT
    cvpn_nf = ("InvalidClientVpnEndpointId.NotFound",)

    problems = _probe_errors([
        (
            "create_client_vpn_route",
            lambda: ec2.create_client_vpn_route(
                ClientVpnEndpointId=a["cvpn"],
                DestinationCidrBlock="10.0.0.0/24",
                TargetVpcSubnetId=a["subnet"],
            ),
            cvpn_nf,
        ),
        ("delete_client_vpn_endpoint",
         lambda: ec2.delete_client_vpn_endpoint(ClientVpnEndpointId=a["cvpn"]), cvpn_nf),
        (
            "delete_client_vpn_route",
            lambda: ec2.delete_client_vpn_route(
                ClientVpnEndpointId=a["cvpn"], DestinationCidrBlock="10.0.0.0/24"
            ),
            cvpn_nf,
        ),
        (
            "create_coip_pool",
            lambda: ec2.create_coip_pool(LocalGatewayRouteTableId=a["lgw_rtb"]),
            ("InvalidLocalGatewayRouteTableID.NotFound",),
        ),
        ("create_coip_cidr",
         lambda: ec2.create_coip_cidr(Cidr="10.0.0.0/24", CoipPoolId=a["coip_pool"]),
         ("InvalidPoolID.NotFound",)),
        ("delete_coip_pool", lambda: ec2.delete_coip_pool(CoipPoolId=a["coip_pool"]),
         ("InvalidParameterValue",)),
        ("delete_coip_cidr",
         lambda: ec2.delete_coip_cidr(Cidr="10.0.0.0/24", CoipPoolId=a["coip_pool"]),
         ("InvalidPoolID.NotFound",)),
    ])
    assert not problems, "unexpected client-VPN/COIP error semantics:\n" + "\n".join(problems)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
