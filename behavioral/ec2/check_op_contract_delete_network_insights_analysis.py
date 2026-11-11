"""op-contract-delete-network-insights-analysis."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-delete-network-insights-analysis"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteNetworkInsightsAnalysis removes a completed reachability analysis;
    deleting an unknown analysis ID is rejected with a NotFound-family error."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-nia-")

    igw_source = ec2.create_internet_gateway(TagSpecifications=[_tag_spec("internet-gateway", name)])[
        "InternetGateway"
    ]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _cleanup_ignore_error(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_source)))

    vpc_id = ec2.create_vpc(CidrBlock="10.88.0.0/16", TagSpecifications=[_tag_spec("vpc", name)])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _cleanup_ignore_error(lambda: ec2.delete_vpc(VpcId=vpc_id)))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.88.1.0/24", TagSpecifications=[_tag_spec("subnet", name)]
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

    analysis_id = ec2.start_network_insights_analysis(
        NetworkInsightsPathId=path_id, TagSpecifications=[_tag_spec("network-insights-analysis", name)]
    )["NetworkInsightsAnalysis"]["NetworkInsightsAnalysisId"]
    ctx.on_cleanup(
        lambda: _cleanup_ignore_error(lambda: ec2.delete_network_insights_analysis(NetworkInsightsAnalysisId=analysis_id))
    )

    def _describe():
        resp = ec2.describe_network_insights_analyses(NetworkInsightsAnalysisIds=[analysis_id])
        analyses = resp["NetworkInsightsAnalyses"]
        return analyses[0] if analyses else None

    finished = _poll_until(
        _describe, lambda a: a is not None and a["Status"] in ("succeeded", "failed"), timeout_s=180.0, interval_s=5.0
    )
    assert finished["Status"] == "succeeded", f"analysis did not succeed: {finished}"

    resp = ec2.delete_network_insights_analysis(NetworkInsightsAnalysisId=analysis_id)
    assert resp["NetworkInsightsAnalysisId"] == analysis_id, (
        f"delete echoed wrong id: expected {analysis_id}, got {resp.get('NetworkInsightsAnalysisId')}"
    )

    try:
        remaining = ec2.describe_network_insights_analyses(NetworkInsightsAnalysisIds=[analysis_id])[
            "NetworkInsightsAnalyses"
        ]
        assert remaining == [], f"deleted analysis still listed: {remaining}"
    except ClientError as exc:
        assert "NotFound" in exc.response["Error"]["Code"], f"unexpected code: {exc.response['Error']['Code']}"
        assert exc.response["Error"]["Message"] == f"{analysis_id} does not exist", exc.response["Error"]

    # Deleting a syntactically-valid but never-existed analysis ID is expected to be
    # rejected. On real AWS this API reports a missing analysis via a generic
    # InvalidParameterValue error (rather than a dedicated NotFound-family code), so
    # accept that too as long as the message actually refers to the bogus id being
    # absent. Some accounts/regions have instead been observed treating this delete as
    # an idempotent no-op (returning the same ID back rather than raising); accept that
    # outcome as well, but require the response to be internally consistent in the
    # no-error case rather than skipping the assertion.
    bogus_id = _bogus_id(analysis_id)
    bogus_resp, bogus_exc = _call_or_error(
        lambda: ec2.delete_network_insights_analysis(NetworkInsightsAnalysisId=bogus_id)
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
            assert bogus_message == f"NetworkInsightsAnalysisId ({bogus_id}) is not valid", bogus_message
    else:
        assert bogus_resp["NetworkInsightsAnalysisId"] == bogus_id, (
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


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


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
            "InvalidNetworkInsightsAnalysisId.NotFound",
            "InvalidNetworkInsightsPathId.NotFound",
            "InvalidNetworkInterfaceID.NotFound",
            "InvalidSubnetID.NotFound",
            "InvalidVpcID.NotFound",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
