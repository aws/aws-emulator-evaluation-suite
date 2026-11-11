"""insights-refresh-in-progress-to-complete-transition."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "insights-refresh-in-progress-to-complete-transition"
GROUP = "state-machine"
SERVICES = ["eks"]

_CLUSTER_WAIT_TIMEOUT_S = 20 * 60
_CLUSTER_POLL_INTERVAL_S = 20
_INSIGHTS_WAIT_TIMEOUT_S = 10 * 60
# Cluster insights can stay unavailable (StartInsightsRefresh 404s) for more than 10 minutes
# after the cluster reports ACTIVE.
_INSIGHTS_READY_TIMEOUT_S = 1100
_INSIGHTS_POLL_INTERVAL_S = 2


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A cluster insights refresh (explicit or the one EKS auto-schedules for a new cluster) reports
    IN_PROGRESS, then DescribeInsightsRefresh reaches COMPLETED with startedAt/endedAt and does
    not regress to IN_PROGRESS."""
    eks = ctx.client("eks")
    cluster_name = _create_active_cluster(ctx)

    # StartInsightsRefresh 404s until insights are available for a new cluster, and 409s
    # "already in progress" while EKS's own first scheduled refresh runs; that refresh is the
    # same state machine, so it is observed instead.
    started = _poll_until(
        lambda: _try_start_insights_refresh(eks, cluster_name),
        lambda r: r is not None,
        timeout_s=_INSIGHTS_READY_TIMEOUT_S,
        interval_s=_INSIGHTS_POLL_INTERVAL_S,
    )
    assert started["status"] == "IN_PROGRESS", started

    terminal = _poll_until(
        lambda: _read_refresh(eks, cluster_name),
        lambda r: r["status"] in ("COMPLETED", "FAILED"),
        timeout_s=_INSIGHTS_WAIT_TIMEOUT_S,
        interval_s=_INSIGHTS_POLL_INTERVAL_S,
    )
    assert terminal["status"] == "COMPLETED", (
        f"insights refresh ended in {terminal['status']}: {terminal.get('message')}"
    )
    assert "startedAt" in terminal and "endedAt" in terminal, (
        f"expected startedAt and endedAt on a terminal refresh, got keys {sorted(terminal)}"
    )

    # A terminal refresh must not regress back to IN_PROGRESS on its own.
    for _ in range(5):
        time.sleep(3)
        still = eks.describe_insights_refresh(clusterName=cluster_name)
        assert still["status"] == "COMPLETED", f"terminal insights refresh regressed to {still['status']}"


# ===== helpers =====


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


def _try_start_insights_refresh(eks, cluster_name: str):
    try:
        return eks.start_insights_refresh(clusterName=cluster_name)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "ResourceNotFoundException":
            return None
        if code == "InvalidRequestException" and "already in progress" in exc.response["Error"].get("Message", ""):
            # EKS's own auto-scheduled refresh won the race; it is the same
            # IN_PROGRESS -> terminal transition this check is verifying, so read it
            # independently instead of treating the conflict as a failure.
            return eks.describe_insights_refresh(clusterName=cluster_name)
        raise


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _create_network(ctx) -> list[str]:
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.42.0.0/16",
        TagSpecifications=[_tag_spec("vpc", ctx.unique_name("sim2real-eks-vpc-"))],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))

    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    az_names = [az["ZoneName"] for az in azs][:2]
    assert len(az_names) >= 2, "region needs at least two availability zones"

    subnet_ids = []
    for i, az in enumerate(az_names):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.42.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec("subnet", ctx.unique_name(f"sim2real-eks-subnet{i}-"))],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _retry_delete(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _create_cluster_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _delete_cluster_and_wait(ctx, name: str) -> None:
    eks = ctx.client("eks")
    try:
        eks.delete_cluster(name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    deadline = time.monotonic() + _CLUSTER_WAIT_TIMEOUT_S
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(_CLUSTER_POLL_INTERVAL_S)
    raise AssertionError(f"cluster {name} was not deleted within {_CLUSTER_WAIT_TIMEOUT_S}s")


def _retry_delete(fn) -> None:
    """Run a network delete (fn retries DependencyViolation itself); an already-gone resource
    counts as deleted and every other error raises."""
    try:
        fn()
    except ClientError as exc:
        if not exc.response["Error"]["Code"].endswith(".NotFound"):
            raise


def _create_active_cluster(ctx) -> str:
    eks = ctx.client("eks")
    subnet_ids = _create_network(ctx)
    role_arn = _create_cluster_role(ctx)
    name = ctx.unique_name("sim2real-eks-cluster-")

    # The just-created role is rejected (InvalidParameterException) until IAM propagates it:
    # retry every 2 s up to 80 s, capped by the run's remaining time.
    retry_deadline = time.monotonic() + 80.0
    left = ctx.time_left()
    if left is not None:
        retry_deadline = min(retry_deadline, time.monotonic() + max(1.0, left - 5.0))
    while True:
        try:
            eks.create_cluster(name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnet_ids})
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterException" or time.monotonic() >= retry_deadline:
                raise
        time.sleep(2)

    ctx.on_cleanup(lambda: _delete_cluster_and_wait(ctx, name))

    active = _poll_until(
        lambda: eks.describe_cluster(name=name)["cluster"],
        lambda c: c["status"] in ("ACTIVE", "FAILED"),
        timeout_s=_CLUSTER_WAIT_TIMEOUT_S,
        interval_s=_CLUSTER_POLL_INTERVAL_S,
    )
    assert active["status"] == "ACTIVE", f"cluster ended in status {active['status']}"
    return name


# A cluster or other resource in this VPC deletes asynchronously and leaves its ENIs behind for a while,
# so an immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Teardown
# waits (bounded) for the ENIs, retries DependencyViolation in one window shared by the check's network
# deletes, then raises naming any ENIs still attached. Teardown-only: run() never calls this.
_NET_TEARDOWN_S = 1260.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(2)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(2)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


def _read_refresh(eks, cluster_name):
    """DescribeInsightsRefresh inside a poll, tolerating the brief window after StartInsightsRefresh
    in which the new refresh is not yet readable (404 "No insights refresh found")."""
    try:
        return eks.describe_insights_refresh(clusterName=cluster_name)
    except eks.exceptions.ResourceNotFoundException:
        return {"status": None}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
