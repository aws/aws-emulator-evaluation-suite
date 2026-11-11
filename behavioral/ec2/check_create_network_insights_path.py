"""create-network-insights-path."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-network-insights-path"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_BAD_SOURCE = "sim2real-unclassifiable-source"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateNetworkInsightsPath between two ENIs returns an nip- path whose Source, Destination and Protocol tcp
    read back the same, while a Source of no known resource type is refused with InvalidParameterValue and its
    exact message and leaves no path.
    """
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-nip-")

    vpc_id = ec2.create_vpc(CidrBlock="10.73.0.0/16", TagSpecifications=[_tag_spec("vpc", name)])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.73.1.0/24", TagSpecifications=[_tag_spec("subnet", name)]
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    eni1 = ec2.create_network_interface(
        SubnetId=subnet_id, TagSpecifications=[_tag_spec("network-interface", name)]
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni1))
    eni2 = ec2.create_network_interface(
        SubnetId=subnet_id, TagSpecifications=[_tag_spec("network-interface", name)]
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni2))

    resp = ec2.create_network_insights_path(
        Source=eni1,
        Destination=eni2,
        Protocol="tcp",
        ClientToken=ctx.unique_name("sim2real-behav-nip-"),
        TagSpecifications=[_tag_spec("network-insights-path", name)],
    )
    path = resp["NetworkInsightsPath"]
    path_id = path["NetworkInsightsPathId"]
    ctx.on_cleanup(lambda: ec2.delete_network_insights_path(NetworkInsightsPathId=path_id))

    assert path_id.startswith("nip-"), f"unexpected path id shape: {path_id!r}"

    # Independent read: the create response is never the verdict on its own --
    # confirm the same fields are visible through DescribeNetworkInsightsPaths.
    described = ec2.describe_network_insights_paths(NetworkInsightsPathIds=[path_id])["NetworkInsightsPaths"]
    assert len(described) == 1, f"expected exactly one described path for {path_id!r}, got {described!r}"
    seen = described[0]
    assert seen["Source"] == eni1, f"expected Source {eni1!r}, got {seen.get('Source')!r}"
    assert seen["Destination"] == eni2, f"expected Destination {eni2!r}, got {seen.get('Destination')!r}"
    assert seen["Protocol"] == "tcp", f"expected Protocol tcp, got {seen.get('Protocol')!r}"

    code, message = _error_code(
        lambda: ec2.create_network_insights_path(
            Source=_BAD_SOURCE,
            Destination=eni2,
            Protocol="tcp",
            ClientToken=ctx.unique_name("sim2real-behav-nip-bad-"),
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r} ({message!r})"
    expected_message = (
        f"{_BAD_SOURCE} is not a supported Source type. Supported Source types include: "
        "[instance, network-interface, internet-gateway, vpn-gateway, vpc-endpoint, "
        "vpc-endpoint-service, vpc-peering-connection, transit-gateway, transit-gateway-attachment]"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect-absent, via the same independent read: the rejected attempt must
    # not have left a dangling path behind with the unclassifiable source.
    dangling = ec2.describe_network_insights_paths(Filters=[{"Name": "source", "Values": [_BAD_SOURCE]}])[
        "NetworkInsightsPaths"
    ]
    assert dangling == [], f"expected no path created for the rejected source, got {dangling!r}"


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected CreateNetworkInsightsPath to fail for an unclassifiable source id")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
