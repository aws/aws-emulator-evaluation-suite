"""vpn-and-vpc-config-error-semantics."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _probe_errors(probes):
    """Assert a batch of operations all fail with an expected *server-side* error code.

    *probes* is a list of ``(operation, call, acceptable_codes)``. Every
    mismatch is collected rather than raising on the first. A
    ``ParamValidationError`` is deliberately left uncaught: it means the
    request never left the SDK, so it can never stand in for the server-side
    rejection this probe exists to observe — it must surface as a loud,
    unambiguous failure of the probe's own shape, not get folded into
    ``problems`` alongside genuine code mismatches. Returns the problems.
    """
    problems = []
    for method, call, expected in probes:
        try:
            call()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in expected:
                problems.append(f"{method}: expected {sorted(expected)}, got {code}")
        else:
            problems.append(f"{method}: expected {sorted(expected)} but the call SUCCEEDED")
    return problems


# Well-formed but nonexistent resource ids (17 hex chars after the prefix), so
# probes exercise NotFound semantics rather than id-format rejection.
_ABSENT = {
    "cgw": "cgw-0123456789abcdef0",
    "vpn": "vpn-0123456789abcdef0",
}

CHECK = "vpn-and-vpc-config-error-semantics"
GROUP = 'error-semantics'
SERVICES = ['ec2']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateVpnConnection and CreateVpnConnectionRoute naming unknown ids fail with their listed
    NotFound codes; an endpoint connection notification or service configuration missing required
    parameters fails with InvalidParameter or InvalidParameterCombination/Value."""
    ec2 = ctx.client("ec2")
    a = _ABSENT

    problems = _probe_errors([
        (
            "create_vpn_connection",
            lambda: ec2.create_vpn_connection(
                CustomerGatewayId=a["cgw"],
                Type="ipsec.1",
                VpnGatewayId="vgw-0123456789abcdef0",
            ),
            ("InvalidCustomerGatewayID.NotFound", "InvalidVpnGatewayID.NotFound"),
        ),
        (
            "create_vpn_connection_route",
            lambda: ec2.create_vpn_connection_route(
                VpnConnectionId=a["vpn"],
                DestinationCidrBlock="10.0.0.0/24",
            ),
            ("InvalidVpnConnectionId",),
        ),
        (
            "create_vpc_endpoint_connection_notification",
            lambda: ec2.create_vpc_endpoint_connection_notification(
                ConnectionNotificationArn=f"arn:aws:sns:{ctx.region}:111122223333:nope",
                ConnectionEvents=["Accept"],
            ),
            ("InvalidParameterCombination", "InvalidParameter"),
        ),
        (
            "create_vpc_endpoint_service_configuration",
            lambda: ec2.create_vpc_endpoint_service_configuration(AcceptanceRequired=False),
            ("InvalidParameterValue", "InvalidParameter"),
        ),
    ])
    assert not problems, "unexpected VPN/VPC-config error semantics:\n" + "\n".join(problems)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
