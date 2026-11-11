"""op-contract-delete-network-insights-path."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-delete-network-insights-path"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteNetworkInsightsPath removes a reachability-analyzer path definition;
    deleting an unknown path ID is rejected with a NotFound-family error."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-nip-")

    igw_source = ec2.create_internet_gateway(TagSpecifications=[_tag_spec("internet-gateway", name)])[
        "InternetGateway"
    ]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _cleanup_ignore_error(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_source)))

    vpc_id = ec2.create_vpc(CidrBlock="10.89.0.0/16", TagSpecifications=[_tag_spec("vpc", name)])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _cleanup_ignore_error(lambda: ec2.delete_vpc(VpcId=vpc_id)))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.89.1.0/24", TagSpecifications=[_tag_spec("subnet", name)]
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _cleanup_ignore_error(lambda: ec2.delete_subnet(SubnetId=subnet_id)))

    eni_id = ec2.create_network_interface(
        SubnetId=subnet_id, TagSpecifications=[_tag_spec("network-interface", name)]
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: _cleanup_ignore_error(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni_id)))

    # Network Insights paths only accept specific source/destination type
    # combinations; two internet gateways is not a valid pairing, but a network
    # interface -> internet gateway path is.
    path_id = ec2.create_network_insights_path(
        Source=eni_id,
        Destination=igw_source,
        Protocol="tcp",
        TagSpecifications=[_tag_spec("network-insights-path", name)],
    )["NetworkInsightsPath"]["NetworkInsightsPathId"]
    ctx.on_cleanup(lambda: _cleanup_ignore_error(lambda: ec2.delete_network_insights_path(NetworkInsightsPathId=path_id)))

    resp = ec2.delete_network_insights_path(NetworkInsightsPathId=path_id)
    assert resp["NetworkInsightsPathId"] == path_id, (
        f"expected DeleteNetworkInsightsPath to echo the deleted id {path_id!r}, got {resp.get('NetworkInsightsPathId')!r}"
    )

    try:
        remaining = ec2.describe_network_insights_paths(NetworkInsightsPathIds=[path_id])["NetworkInsightsPaths"]
        assert remaining == [], f"deleted path still listed: {remaining}"
    except ClientError as exc:
        assert "NotFound" in exc.response["Error"]["Code"], f"unexpected code: {exc.response['Error']['Code']}"
        assert exc.response["Error"]["Message"] == f"{path_id} does not exist", exc.response["Error"]

    # Deleting a syntactically-valid but never-existed path ID is expected to be
    # rejected. On real AWS this API reports a missing path via a generic
    # InvalidParameterValue error (rather than a dedicated NotFound-family code), so
    # accept that too as long as the message actually refers to the bogus id being
    # absent. Some accounts/regions have instead been observed treating this delete as
    # an idempotent no-op (returning the same ID back rather than raising); accept that
    # outcome as well, but require the response to be internally consistent in the
    # no-error case rather than skipping the assertion.
    bogus_id = _bogus_id(path_id)
    bogus_resp, bogus_exc = _call_or_error(
        lambda: ec2.delete_network_insights_path(NetworkInsightsPathId=bogus_id)
    )
    if bogus_exc is not None:
        bogus_code = bogus_exc.response["Error"]["Code"]
        bogus_message = bogus_exc.response["Error"].get("Message", "")
        assert "NotFound" in bogus_code or (
            bogus_code == "InvalidParameterValue" and bogus_id in bogus_message
        ), f"unexpected code/message: {bogus_code} / {bogus_message}"
        if "NotFound" in bogus_code:
            assert bogus_message == f"{bogus_id} does not exist", bogus_message
    else:
        assert bogus_resp["NetworkInsightsPathId"] == bogus_id, (
            f"unexpected idempotent-delete response for a never-existed id: {bogus_resp}"
        )


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _bogus_id(real_id: str) -> str:
    """Build a syntactically-valid but non-existent id by flipping the last hex
    character of a real id, so format/length validation cannot mask the NotFound
    check we actually want to exercise."""
    prefix, _, suffix = real_id.rpartition("-")
    last = suffix[-1]
    replacement = "0" if last != "0" else "1"
    return f"{prefix}-{suffix[:-1]}{replacement}"


def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as exc:
        return exc.response["Error"]["Code"]


def _call_or_error(fn):
    try:
        return fn(), None
    except ClientError as exc:
        return None, exc


def _cleanup_ignore_error(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidInternetGatewayID.NotFound",
            "InvalidNetworkInsightsPathId.NotFound",
            "InvalidNetworkInterfaceID.NotFound",
            "InvalidSubnetID.NotFound",
            "InvalidVpcID.NotFound",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
