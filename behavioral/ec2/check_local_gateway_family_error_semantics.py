"""local-gateway-family-error-semantics."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _probe_errors(client, probes):
    """Assert a batch of operations all fail with an expected error code.

    *probes* is a list of ``(client_method, kwargs, acceptable_codes)``. Every
    mismatch is collected rather than raising on the first, and operations the
    installed botocore does not know about are reported as skipped. Returns
    ``(problems, skipped)``.

    A client-side ``ParamValidationError`` is intentionally left uncaught: every probe here is
    well-formed (verified against real AWS), so the SDK rejecting one locally would mean the probe's
    own inputs regressed, not that the target has unexpected error semantics — that must crash
    loudly.
    """
    problems = []
    skipped = []
    for method, kwargs, expected in probes:
        fn = getattr(client, method, None)
        if fn is None:
            skipped.append(method)
            continue
        try:
            fn(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in expected:
                problems.append(f"{method}: expected {sorted(expected)}, got {code}")
        else:
            problems.append(f"{method}: expected {sorted(expected)} but the call SUCCEEDED")
    return problems, skipped


# Well-formed but nonexistent resource ids (17 hex chars after the prefix), so
# probes exercise NotFound semantics rather than id-format rejection.
_ABSENT = {
    "lgw": "lgw-0123456789abcdef0",
    "lgw_rtb": "lgw-rtb-0123456789abcdef0",
    "lgw_vif": "lgw-vif-0123456789abcdef0",
    "lgw_vif_grp": "lgw-vif-grp-0123456789abcdef0",
    "vpc": "vpc-0123456789abcdef0",
}

CHECK = "local-gateway-family-error-semantics"
GROUP = 'error-semantics'
SERVICES = ['ec2']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Outpost local-gateway operations must reject unknown gateway/route-table ids."""
    ec2 = ctx.client("ec2")
    a = _ABSENT
    # NOTE: this family spells the id suffix "ID" (capitalised), unlike the
    # IPAM family which uses "Id".
    lgw_rtb_nf = ("InvalidLocalGatewayRouteTableID.NotFound",)
    lgw_nf = ("InvalidLocalGatewayID.NotFound",)
    param = ("InvalidParameterValue",)

    problems, _ = _probe_errors(ec2, [
        (
            "create_local_gateway_route",
            {"LocalGatewayRouteTableId": a["lgw_rtb"], "DestinationCidrBlock": "10.0.0.0/24"},
            param,
        ),
        ("create_local_gateway_route_table", {"LocalGatewayId": a["lgw"]}, lgw_nf),
        (
            "create_local_gateway_route_table_vpc_association",
            {"LocalGatewayRouteTableId": a["lgw_rtb"], "VpcId": a["vpc"]},
            lgw_rtb_nf + ("InvalidVpcID.NotFound", "InvalidVpcId.NotFound"),
        ),
        (
            "create_local_gateway_route_table_virtual_interface_group_association",
            {
                "LocalGatewayRouteTableId": a["lgw_rtb"],
                "LocalGatewayVirtualInterfaceGroupId": a["lgw_vif_grp"],
            },
            lgw_rtb_nf,
        ),
        ("create_local_gateway_virtual_interface_group", {"LocalGatewayId": a["lgw"]}, lgw_nf),
        (
            "delete_local_gateway_route",
            {"LocalGatewayRouteTableId": a["lgw_rtb"], "DestinationCidrBlock": "10.0.0.0/24"},
            lgw_rtb_nf,
        ),
        (
            "delete_local_gateway_route_table",
            {"LocalGatewayRouteTableId": a["lgw_rtb"]},
            lgw_rtb_nf,
        ),
        (
            "delete_local_gateway_virtual_interface",
            {"LocalGatewayVirtualInterfaceId": a["lgw_vif"]},
            ("InvalidLocalGatewayVirtualInterfaceID.NotFound",),
        ),
        (
            "delete_local_gateway_virtual_interface_group",
            {"LocalGatewayVirtualInterfaceGroupId": a["lgw_vif_grp"]},
            ("InvalidLocalGatewayVirtualInterfaceGroupID.NotFound",),
        ),
    ])
    assert not problems, "unexpected local-gateway error semantics:\n" + "\n".join(problems)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
