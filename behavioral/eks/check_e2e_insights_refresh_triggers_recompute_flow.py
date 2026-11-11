"""e2e-insights-refresh-triggers-recompute-flow."""
from __future__ import annotations

import datetime
import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "e2e-insights-refresh-triggers-recompute-flow"
GROUP = "e2e"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartInsightsRefresh recomputes insights: the refresh goes IN_PROGRESS -> COMPLETED, and
    ListInsights and DescribeInsight agree on an insight whose lastRefreshTime is at or after
    the refresh start, so the refresh is not a no-op acknowledgement."""
    eks = ctx.client("eks")

    subnet_ids = _create_network(ctx)
    cluster_role_arn = _create_role(
        ctx, "cluster", "eks.amazonaws.com", ["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"]
    )

    cluster_name = ctx.unique_name("sim2real-eks-cl-")
    _create_cluster_with_retry(ctx, cluster_name, cluster_role_arn, subnet_ids)
    ctx.on_cleanup(lambda: _best_effort(lambda: eks.delete_cluster(name=cluster_name)))
    _wait_cluster_status(ctx, cluster_name, {"ACTIVE"}, timeout_s=1200)

    # Whole seconds: lastRefreshTime is serialized at second precision.
    t0 = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)

    start = _start_insights_refresh_with_retry(ctx, cluster_name, timeout_s=1100)
    assert start["status"] == "IN_PROGRESS", f"StartInsightsRefresh returned status={start['status']!r}, want IN_PROGRESS"

    final = _poll_insights_refresh(ctx, cluster_name, {"COMPLETED", "FAILED"}, timeout_s=300)
    assert final["status"] == "COMPLETED", f"insights refresh ended in {final['status']}: {final.get('message')}"

    insights = eks.list_insights(clusterName=cluster_name)["insights"]
    assert len(insights) > 0, "ListInsights returned nothing after a completed refresh"

    sample = insights[0]
    detail = eks.describe_insight(clusterName=cluster_name, id=sample["id"])["insight"]
    assert detail["insightStatus"]["status"] == sample["insightStatus"]["status"], (
        f"insight {sample['id']}: ListInsights reported status "
        f"{sample['insightStatus']['status']!r} but DescribeInsight reported "
        f"{detail['insightStatus']['status']!r} for the same id"
    )
    assert detail["lastRefreshTime"] == sample["lastRefreshTime"], (
        f"insight {sample['id']}: ListInsights lastRefreshTime={sample['lastRefreshTime']} "
        f"disagrees with DescribeInsight lastRefreshTime={detail['lastRefreshTime']}"
    )
    assert detail["lastRefreshTime"] >= t0, (
        f"insight {sample['id']} lastRefreshTime={detail['lastRefreshTime']} predates the "
        f"refresh we started at {t0}; refresh did not actually recompute the finding"
    )

    eks.delete_cluster(name=cluster_name)
    _wait_cluster_deleted(ctx, cluster_name, timeout_s=900)


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFoundException"):
            raise


def _delete_with_retry(fn):
    """Run a network delete (_delete_net retries DependencyViolation); an already-gone
    VPC or subnet is a clean teardown, any other failure raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound"):
            raise


def _create_network(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.45.0.0/16",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-vpc-")}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    azs = [
        a["ZoneName"] for a in ec2.describe_availability_zones()["AvailabilityZones"] if a["State"] == "available"
    ][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.45.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-eks-sn{i}-")}]}
            ],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_with_retry(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _create_role(ctx, kind, trust_service, managed_policy_arns):
    iam = ctx.client("iam")
    name = ctx.unique_name(f"sim2real-eks-{kind}-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}],
        }
    )
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    for policy_arn in managed_policy_arns:
        iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)

    def _cleanup():
        for policy_arn in managed_policy_arns:
            _best_effort(lambda p=policy_arn: iam.detach_role_policy(RoleName=name, PolicyArn=p))
        _best_effort(lambda: iam.delete_role(RoleName=name))

    ctx.on_cleanup(_cleanup)
    return arn


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _create_cluster_with_retry(ctx, name, role_arn, subnet_ids, timeout_s=90):
    from botocore.exceptions import ClientError

    eks = ctx.client("eks")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last_err = None
    while time.monotonic() < deadline:
        try:
            eks.create_cluster(name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnet_ids})
            return
        except ClientError as err:
            last_err = err
            code = err.response["Error"]["Code"]
            if code in ("InvalidParameterException", "ClientException"):
                time.sleep(2)
                continue
            raise
    if _budget_spent(ctx):
        raise TimeoutError(f"CreateCluster {name} past IAM propagation: the run budget ended first; not graded")
    raise AssertionError(f"create_cluster never succeeded (IAM propagation?): {last_err}")


def _wait_cluster_status(ctx, name, target_statuses, timeout_s, interval_s=2):
    eks = ctx.client("eks")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = eks.describe_cluster(name=name)["cluster"]["status"]
        if last in target_statuses:
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"cluster {name} reaching {target_statuses}: the run budget ended first; not graded")
    raise AssertionError(f"cluster {name} status {last} never reached {target_statuses}")


def _wait_cluster_deleted(ctx, name, timeout_s, interval_s=2):
    from botocore.exceptions import ClientError

    eks = ctx.client("eks")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"cluster {name} deleted: the run budget ended first; not graded")
    raise AssertionError(f"cluster {name} was not deleted within {timeout_s}s")


def _poll_insights_refresh(ctx, cluster_name, target_statuses, timeout_s, interval_s=2):
    eks = ctx.client("eks")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = eks.describe_insights_refresh(clusterName=cluster_name)
        if last["status"] in target_statuses:
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"insights refresh reaching {target_statuses}: the run budget ended first; not graded")
    raise AssertionError(f"insights refresh status {last} never reached {target_statuses}")


def _start_insights_refresh_with_retry(ctx, cluster_name, timeout_s, interval_s=2):
    """StartInsightsRefresh, retrying until insights are available (up to 15 minutes after ACTIVE)
    and until AWS's own scheduled refresh, which runs soon after ACTIVE, is no longer in flight."""
    from botocore.exceptions import ClientError

    eks = ctx.client("eks")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last_err = None
    while time.monotonic() < deadline:
        try:
            return eks.start_insights_refresh(clusterName=cluster_name)
        except ClientError as err:
            last_err = err
            code = err.response["Error"]["Code"]
            message = str(err).lower()
            if code == "ResourceNotFoundException" and "cluster insights" in message:
                time.sleep(interval_s)
                continue
            if code == "InvalidRequestException" and "already in progress" in message:
                time.sleep(interval_s)
                continue
            raise
    if _budget_spent(ctx):
        raise TimeoutError(f"insights refresh on {cluster_name} becoming startable: the run budget ended first; not graded")
    raise AssertionError(f"cluster insights refresh never became startable: {last_err}")


# EC2 network teardown waits for AWS-managed ENIs to leave before deleting: dependents in the VPC
# delete asynchronously, so an immediate DeleteSubnet/DeleteVpc fails with DependencyViolation.
# The bounded window is shared by all of one check's network deletes and fits the cleanup budget.
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
