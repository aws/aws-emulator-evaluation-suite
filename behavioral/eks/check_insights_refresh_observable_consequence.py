"""insights-refresh-observable-consequence."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "insights-refresh-observable-consequence"
GROUP = "e2e"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartInsightsRefresh's real, observable effect is a fresh lastRefreshTime on the
    cluster's insights as seen through ListInsights -- not merely a COMPLETED terminal
    status on the refresh operation itself."""
    eks = ctx.client("eks")
    cluster_name = _create_active_cluster(
        ctx, access_config={"authenticationMode": "API_AND_CONFIG_MAP"}
    )

    # Insights are computed asynchronously and are not guaranteed to exist the instant the
    # cluster reaches ACTIVE. Force an on-demand refresh right away so the first batch of
    # UPGRADE_READINESS insights gets published deterministically rather than waiting on
    # EKS's internal ~24h schedule. Immediately after the cluster reaches ACTIVE, EKS may
    # still report the cluster as "not available yet" for insights (ResourceNotFoundException)
    # or may already have an automatic initial refresh in flight
    # (InvalidRequestException, "already in progress"); retry through either transient
    # state on a bounded window rather than treating it as fatal.
    first_start = _start_insights_refresh_with_retry(eks, cluster_name, timeout_s=900, interval_s=20)
    assert first_start["status"] in ("IN_PROGRESS", "COMPLETED"), (
        f"expected StartInsightsRefresh to report IN_PROGRESS or COMPLETED, got {first_start!r}"
    )

    first_refresh = _poll_until(
        lambda: eks.describe_insights_refresh(clusterName=cluster_name),
        lambda r: r["status"] in ("COMPLETED", "FAILED"),
        timeout_s=600,
        interval_s=15,
    )
    assert first_refresh["status"] == "COMPLETED", (
        f"initial insights refresh did not complete: {first_refresh}"
    )

    baseline = _poll_until(
        lambda: eks.list_insights(clusterName=cluster_name)["insights"],
        lambda insights: len(insights) > 0,
        timeout_s=600,
        interval_s=15,
    )
    insight_name = baseline[0]["name"]
    baseline_refresh_time = baseline[0]["lastRefreshTime"]

    # A refresh EKS started on its own (the automatic schedule, or the residue of the
    # first refresh above) can still be occupying the single-flight slot the instant we
    # try to start our own; retry through that the same way as the first call rather
    # than treating "already in progress" as fatal.
    start = _start_insights_refresh_with_retry(eks, cluster_name, timeout_s=900, interval_s=20)
    assert start["status"] in ("IN_PROGRESS", "COMPLETED"), (
        f"expected StartInsightsRefresh to report IN_PROGRESS or COMPLETED, got {start!r}"
    )

    refresh = _poll_until(
        lambda: eks.describe_insights_refresh(clusterName=cluster_name),
        lambda r: r["status"] in ("COMPLETED", "FAILED"),
        timeout_s=600,
        interval_s=15,
    )
    assert refresh["status"] == "COMPLETED", f"insights refresh did not complete: {refresh}"

    def _current_refresh_time():
        # Match by name (a stable identifier for a given insight check) rather than id,
        # since an insight's id is not guaranteed to be stable across refresh cycles.
        insights = eks.list_insights(clusterName=cluster_name)["insights"]
        match = next((i for i in insights if i["name"] == insight_name), None)
        return match["lastRefreshTime"] if match else None

    updated_time = _poll_until(
        _current_refresh_time,
        lambda t: t is not None and t > baseline_refresh_time,
        timeout_s=300,
        interval_s=10,
    )
    assert updated_time > baseline_refresh_time, (
        f"insight {insight_name!r} lastRefreshTime did not advance past "
        f"{baseline_refresh_time} after StartInsightsRefresh completed"
    )


# ===== helpers =====


_GONE = {"NoSuchEntity", "ResourceNotFoundException", "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound"}


def _safe(fn: Callable[[], Any], timeout_s: float = 300.0) -> None:
    """Teardown delete: an already-gone resource counts as deleted; DependencyViolation (ENIs of a
    deleted cluster still releasing) is retried every 2 s up to timeout_s; anything else raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in _GONE:
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _start_insights_refresh_with_retry(
    eks, cluster_name: str, *, timeout_s: float, interval_s: float
) -> dict[str, Any]:
    """StartInsightsRefresh can transiently refuse for two different reasons that are
    not the fidelity question this check is asking: EKS may still report the cluster
    as "not available yet" for insights (ResourceNotFoundException) right after it
    reaches ACTIVE, or a refresh EKS started on its own may already be occupying the
    single-flight slot (InvalidRequestException, "already in progress"). Retry through
    both on a bounded window; anything else is a real rejection and propagates."""
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return eks.start_insights_refresh(clusterName=cluster_name)
        except ClientError as exc:
            error = exc.response["Error"]
            code = error["Code"]
            message = error.get("Message", "")
            if code == "ResourceNotFoundException" and "available yet" in message:
                last_err = exc
                time.sleep(interval_s)
                continue
            if code == "InvalidRequestException" and "already in progress" in message:
                last_err = exc
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(
        f"StartInsightsRefresh for {cluster_name} never got accepted within {timeout_s}s: {last_err}"
    )



def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 3.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed: {last!r}")


def _tag_specs(resource_type: str, name: str) -> list[dict[str, Any]]:
    return [
        {
            "ResourceType": resource_type,
            "Tags": [
                {"Key": "Name", "Value": name},
                {"Key": "sim2real", "Value": "eks-behavioral"},
            ],
        }
    ]


def _create_vpc_and_subnets(ctx) -> tuple[str, list[str]]:
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.44.0.0/16",
        TagSpecifications=_tag_specs("vpc", ctx.unique_name("sim2real-eks-vpc-")),
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    subnet_ids = []
    for i, cidr_block in enumerate(("10.44.0.0/24", "10.44.1.0/24")):
        az = azs[i % len(azs)]["ZoneName"]
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=cidr_block,
            AvailabilityZone=az,
            TagSpecifications=_tag_specs("subnet", ctx.unique_name(f"sim2real-eks-subnet{i}-")),
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)
        ctx.on_cleanup(lambda sid=subnet_id: _safe(lambda: ec2.delete_subnet(SubnetId=sid)))
    return vpc_id, subnet_ids


def _create_cluster_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-clusterrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))[
        "Role"
    ]["Arn"]
    iam.attach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    )

    def _cleanup():
        _safe(
            lambda: iam.detach_role_policy(
                RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
            )
        )
        _safe(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_cluster_with_retry(ctx, **kwargs) -> dict[str, Any]:
    eks = ctx.client("eks")
    deadline = time.monotonic() + 90
    while True:
        try:
            return eks.create_cluster(**kwargs)["cluster"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidParameterException" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise


def _wait_cluster_active(ctx, name: str, timeout_s: float = 1500.0, interval_s: float = 20.0) -> None:
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = eks.describe_cluster(name=name)["cluster"]["status"]
        if status == "ACTIVE":
            return
        if status == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED while waiting for ACTIVE")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} did not reach ACTIVE within {timeout_s}s (last={status})")


def _delete_cluster_and_wait(ctx, name: str, timeout_s: float = 900.0, interval_s: float = 15.0) -> None:
    eks = ctx.client("eks")
    _safe(lambda: eks.delete_cluster(name=name))
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} was not deleted within {timeout_s}s")


def _create_active_cluster(ctx, access_config: dict[str, Any] | None = None) -> str:
    _vpc_id, subnet_ids = _create_vpc_and_subnets(ctx)
    role_arn = _create_cluster_role(ctx)
    name = ctx.unique_name("sim2real-eks-")
    kwargs: dict[str, Any] = {
        "name": name,
        "roleArn": role_arn,
        "resourcesVpcConfig": {"subnetIds": subnet_ids},
    }
    if access_config:
        kwargs["accessConfig"] = access_config
    _create_cluster_with_retry(ctx, **kwargs)
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(ctx, name))
    _wait_cluster_active(ctx, name)
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
