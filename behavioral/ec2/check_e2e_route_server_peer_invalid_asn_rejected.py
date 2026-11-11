"""e2e-route-server-peer-invalid-asn-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-route-server-peer-invalid-asn-rejected"
GROUP = "e2e"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRouteServerPeer on an unknown endpoint id and DeleteRouteServerPeer on an unknown peer
    id fail with their NotFound codes and exact messages, and a unicode tag value set by
    CreateRouteServer describes back byte-for-byte.
    """
    ec2 = ctx.client("ec2")

    from botocore.exceptions import ClientError

    bogus_endpoint_id = "rse-" + "0" * 17
    try:
        ec2.create_route_server_peer(
            RouteServerEndpointId=bogus_endpoint_id,
            PeerAddress="10.234.1.10",
            BgpOptions={"PeerAsn": 65001},
        )
        raise AssertionError(
            "expected CreateRouteServerPeer against a nonexistent "
            "RouteServerEndpointId to be rejected, but it succeeded"
        )
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "InvalidRouteServerEndpointId.NotFound", (
            f"expected InvalidRouteServerEndpointId.NotFound, got {code!r}"
        )
        message = err.response["Error"].get("Message", "")
        expected = f"The route-server-endpoint ID '{bogus_endpoint_id}' does not exist"
        assert message == expected, f"expected message {expected!r}, got {message!r}"

    bogus_peer_id = "rsp-" + "0" * 17
    try:
        ec2.delete_route_server_peer(RouteServerPeerId=bogus_peer_id)
        raise AssertionError(
            "expected DeleteRouteServerPeer against a nonexistent "
            "RouteServerPeerId to be rejected, but it succeeded"
        )
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "InvalidRouteServerPeerId.NotFound", (
            f"expected InvalidRouteServerPeerId.NotFound, got {code!r}"
        )
        message = err.response["Error"].get("Message", "")
        expected = f"The route-server-peer ID '{bogus_peer_id}' does not exist"
        assert message == expected, f"expected message {expected!r}, got {message!r}"

    # --- Representation fidelity: a unicode/emoji tag value must survive
    # CreateRouteServer -> DescribeRouteServers unchanged, byte-for-byte. ---
    tag_value = ctx.unique_name("sim2real-rs-tag-") + "-\u65e5\u672c\U0001f680"
    rs_id = ec2.create_route_server(
        AmazonSideAsn=64512,
        TagSpecifications=[
            {"ResourceType": "route-server", "Tags": [{"Key": "sim2real-note", "Value": tag_value}]}
        ],
    )["RouteServer"]["RouteServerId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_route_server(RouteServerId=rs_id)))

    described = ec2.describe_route_servers(RouteServerIds=[rs_id])["RouteServers"][0]
    seen = next(t["Value"] for t in described["Tags"] if t["Key"] == "sim2real-note")
    assert seen == tag_value, f"tag value mangled: {seen!r} != {tag_value!r}"


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidRouteServerId.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

