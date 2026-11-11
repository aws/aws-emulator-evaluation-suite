"""transit-gateway-family-error-semantics."""
from __future__ import annotations

from botocore.exceptions import ClientError, ParamValidationError

from behavioral_harness import tags

CHECK = "transit-gateway-family-error-semantics"
GROUP = 'error-semantics'
SERVICES = ['ec2']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Eleven transit gateway create calls naming unknown gateway, attachment or route-table ids (or an
    invalid ASN) each fail with one of their listed NotFound or InvalidParameterValue codes."""
    ec2 = ctx.client("ec2")
    a = _ABSENT
    tgw_nf = ("InvalidTransitGatewayID.NotFound",)
    att_nf = ("InvalidTransitGatewayAttachmentID.NotFound",)

    problems = _probe_errors([
        ("create_transit_gateway_route_table",
         lambda: ec2.create_transit_gateway_route_table(TransitGatewayId=a["tgw"]), tgw_nf),
        ("create_transit_gateway_multicast_domain",
         lambda: ec2.create_transit_gateway_multicast_domain(TransitGatewayId=a["tgw"]), tgw_nf),
        ("create_transit_gateway_policy_table",
         lambda: ec2.create_transit_gateway_policy_table(TransitGatewayId=a["tgw"]), tgw_nf),
        (
            "create_transit_gateway_vpc_attachment",
            lambda: ec2.create_transit_gateway_vpc_attachment(
                TransitGatewayId=a["tgw"],
                VpcId=a["vpc"],
                SubnetIds=[a["subnet"]],
            ),
            tgw_nf + ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound"),
        ),
        (
            "create_transit_gateway_peering_attachment",
            lambda: ec2.create_transit_gateway_peering_attachment(
                TransitGatewayId=a["tgw"],
                PeerTransitGatewayId=a["tgw"],
                PeerAccountId="111122223333",
                PeerRegion=ctx.region,
            ),
            ("InvalidParameterValue",),
        ),
        (
            "create_transit_gateway_connect",
            lambda: ec2.create_transit_gateway_connect(
                TransportTransitGatewayAttachmentId=a["tgw_attach"],
                Options={"Protocol": "gre"},
            ),
            ("InvalidParameterValue",),
        ),
        (
            "create_transit_gateway_connect_peer",
            lambda: ec2.create_transit_gateway_connect_peer(
                TransitGatewayAttachmentId=a["tgw_attach"],
                PeerAddress="203.0.113.10",
                InsideCidrBlocks=["169.254.100.0/29"],
            ),
            att_nf,
        ),
        (
            "create_transit_gateway_route_table_announcement",
            lambda: ec2.create_transit_gateway_route_table_announcement(
                TransitGatewayRouteTableId=a["tgw_rtb"],
                PeeringAttachmentId=a["tgw_attach"],
            ),
            # EC2 surfaces an unknown TGW route table via the generic route-table code.
            ("InvalidRouteTableID.NotFound",),
        ),
        (
            "create_transit_gateway_route",
            lambda: ec2.create_transit_gateway_route(
                DestinationCidrBlock="10.0.0.0/24",
                TransitGatewayRouteTableId=a["tgw_rtb"],
            ),
            ("InvalidRouteTableID.NotFound",),
        ),
        (
            "create_transit_gateway_prefix_list_reference",
            lambda: ec2.create_transit_gateway_prefix_list_reference(
                TransitGatewayRouteTableId=a["tgw_rtb"],
                PrefixListId=a["prefix_list"],
                TransitGatewayAttachmentId=a["tgw_attach"],
            ),
            (
                "InvalidRouteTableID.NotFound",
                "InvalidTransitGatewayAttachmentID.NotFound",
                "InvalidPrefixListID.NotFound",
            ),
        ),
        (
            "create_transit_gateway",
            # ASN outside the assignable private range.
            lambda: ec2.create_transit_gateway(Options={"AmazonSideAsn": 99}),
            ("InvalidParameterValue",),
        ),
    ])
    assert not problems, "unexpected transit-gateway error semantics:\n" + "\n".join(problems)

# Well-formed but nonexistent resource ids (17 hex chars after the prefix), so
# probes exercise NotFound semantics rather than id-format rejection.
_ABSENT = {
    "tgw": "tgw-0123456789abcdef0",
    "tgw_attach": "tgw-attach-0123456789abcdef0",
    "tgw_rtb": "tgw-rtb-0123456789abcdef0",
    "vpc": "vpc-0123456789abcdef0",
    "subnet": "subnet-0123456789abcdef0",
    "prefix_list": "pl-0123456789abcdef0",
}


def _probe_errors(probes):
    """Assert a batch of operations all fail with an expected error code.

    *probes* is a list of ``(operation, call, acceptable_codes)``.

    Every mismatch is collected rather than raising on the first one, so a single
    run reports the real error code for every probe. Returns the problems.
    """
    problems: list[str] = []
    for method, call, expected in probes:
        try:
            call()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in expected:
                problems.append(f"{method}: expected {sorted(expected)}, got {code}")
        except ParamValidationError as exc:
            problems.append(f"{method}: PARAM VALIDATION: {exc}")
        else:
            problems.append(f"{method}: expected {sorted(expected)} but the call SUCCEEDED")
    return problems

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
