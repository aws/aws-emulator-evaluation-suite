"""op-contract-start-network-insights-analysis."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-start-network-insights-analysis"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartNetworkInsightsAnalysis analyzes a real path between two ENIs to a terminal
    status; a bogus path id is rejected."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-snia-")

    vpc_id = ec2.create_vpc(CidrBlock="10.211.0.0/16", TagSpecifications=[_tag_spec("vpc", name)])[
        "Vpc"
    ]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    _wait_vpc_available(ctx, vpc_id)

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.211.1.0/24", TagSpecifications=[_tag_spec("subnet", name)]
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    eni_src = ec2.create_network_interface(
        SubnetId=subnet_id,
        Description="sim2real-behav-src",
        TagSpecifications=[_tag_spec("network-interface", name)],
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni_src))

    eni_dst = ec2.create_network_interface(
        SubnetId=subnet_id,
        Description="sim2real-behav-dst",
        TagSpecifications=[_tag_spec("network-interface", name)],
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni_dst))

    path_id = ec2.create_network_insights_path(
        Source=eni_src,
        Destination=eni_dst,
        Protocol="tcp",
        DestinationPort=80,
        TagSpecifications=[_tag_spec("network-insights-path", name)],
    )["NetworkInsightsPath"]["NetworkInsightsPathId"]
    ctx.on_cleanup(lambda: ec2.delete_network_insights_path(NetworkInsightsPathId=path_id))

    # success path: start analysis and drive it to a terminal status
    resp = ec2.start_network_insights_analysis(
        NetworkInsightsPathId=path_id,
        ClientToken=ctx.unique_name("sim2real-behav-analysis-"),
        TagSpecifications=[_tag_spec("network-insights-analysis", name)],
    )
    analysis_id = resp["NetworkInsightsAnalysis"]["NetworkInsightsAnalysisId"]
    ctx.on_cleanup(
        lambda: ec2.delete_network_insights_analysis(NetworkInsightsAnalysisId=analysis_id)
    )

    def probe():
        resp = ec2.describe_network_insights_analyses(NetworkInsightsAnalysisIds=[analysis_id])
        analyses = resp.get("NetworkInsightsAnalyses", [])
        return analyses[0]["Status"] if analyses else None

    status = _poll_until(probe, lambda s: s in ("succeeded", "failed"), timeout_s=180.0)
    assert status in ("succeeded", "failed"), f"expected succeeded|failed, analysis {analysis_id} reported {status!r}"

    # error boundary: nonexistent path id. The positive control above already proved this
    # account/credential pair can start a real analysis on this operation, so a rejection here
    # is specific to the bogus id, not a blanket denial.
    code, message = _error(
        lambda: ec2.start_network_insights_analysis(
            NetworkInsightsPathId="nip-00000000000000000",
            ClientToken=ctx.unique_name("sim2real-behav-analysis-bad-"),
        )
    )
    assert code == "InvalidParameterValue", (
        f"expected InvalidParameterValue for a bogus path id, got {code!r}"
    )
    assert message == "NetworkInsightsPathId (nip-00000000000000000) is not valid", (
        f"unexpected InvalidParameterValue message {message!r}")


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a call that
    succeeds raises AssertionError."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _wait_vpc_available(ctx, vpc_id, timeout_s=60.0):
    ec2 = ctx.client("ec2")

    def probe():
        resp = ec2.describe_vpcs(VpcIds=[vpc_id])
        return resp["Vpcs"][0]["State"]

    return _poll_until(probe, lambda s: s == "available", timeout_s=timeout_s, interval_s=2.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
