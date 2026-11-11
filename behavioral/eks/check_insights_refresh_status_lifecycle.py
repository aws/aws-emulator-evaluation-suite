"""insights-refresh-status-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "insights-refresh-status-lifecycle"
GROUP = "state-machine"
SERVICES = ["eks"]

_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartInsightsRefresh moves the cluster's refresh status to IN_PROGRESS and
    DescribeInsightsRefresh only ever advances forward (IN_PROGRESS -> COMPLETED), and a read
    after the terminal one still reports COMPLETED with startedAt and endedAt.
    """
    eks = ctx.client("eks")
    cluster = _create_active_eks_cluster(ctx)

    start = _start_insights_refresh_when_ready(ctx, eks, cluster)
    assert start["status"] == "IN_PROGRESS", start

    # The start's own answer is the first status seen, so a target that completes the refresh
    # before the first read still shows IN_PROGRESS -> COMPLETED.
    seen = [start["status"]]
    deadline = time.monotonic() + _budget_s(ctx, 900.0)
    status = None
    while time.monotonic() < deadline:
        resp = eks.describe_insights_refresh(clusterName=cluster)
        status = resp["status"]
        if not seen or seen[-1] != status:
            seen.append(status)
        if status in ("COMPLETED", "FAILED"):
            break
        time.sleep(2)
    else:
        if _budget_spent(ctx):
            raise TimeoutError(f"insights refresh reaching a terminal status: the run budget ended first; not graded ({seen})")

    assert status == "COMPLETED", f"expected refresh to reach COMPLETED, observed sequence {seen}"
    # the observed sequence of *distinct* statuses must be monotonically forward:
    # IN_PROGRESS must appear before COMPLETED, and COMPLETED must not be followed by
    # anything (no reversion back to IN_PROGRESS while we were polling).
    assert seen[0] == "IN_PROGRESS", seen
    assert seen[-1] == "COMPLETED", seen
    assert seen.count("IN_PROGRESS") == 1, f"status reverted to IN_PROGRESS more than once: {seen}"

    # An independent read after the terminal one still reports COMPLETED.
    final = eks.describe_insights_refresh(clusterName=cluster)
    assert final["status"] == "COMPLETED"
    assert "startedAt" in final and "endedAt" in final
    assert final["endedAt"] >= final["startedAt"]


def _start_insights_refresh_when_ready(ctx, eks, cluster, timeout_s=1200.0):
    """StartInsightsRefresh once the cluster's insights accept one: retried while insights still
    lag the cluster going ACTIVE (ResourceNotFoundException "isn't available yet") and while the
    service's own scheduled refresh is running (InvalidRequestException "already in progress")."""
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while True:
        try:
            return eks.start_insights_refresh(clusterName=cluster)
        except ClientError as e:
            err = e.response["Error"]
            msg = err.get("Message", "")
            not_ready = err["Code"] == "ResourceNotFoundException" and "available yet" in msg
            busy = err["Code"] == "InvalidRequestException" and "already in progress" in msg
            if not (not_ready or busy):
                raise
            if time.monotonic() >= deadline:
                if _budget_spent(ctx):
                    raise TimeoutError("starting an insights refresh: the run budget ended first; not graded") from e
                raise
        time.sleep(2)


def _ec2_tags(name):
    return [{"Key": "Name", "Value": name}, {"Key": "sim2real-managed", "Value": "true"}]


def _create_eks_cluster_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_CLUSTER_POLICY)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=_CLUSTER_POLICY)
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_eks_vpc_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.79.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _ec2_tags(ctx.unique_name("sim2real-eks-vpc-"))}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"][:2]]
    subnet_ids = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.79.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _ec2_tags(ctx.unique_name(f"sim2real-eks-sn{i}-"))}],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))
    return subnet_ids


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_cluster_status(ctx, eks, name, target, timeout_s=1200.0):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = eks.describe_cluster(name=name)["cluster"]["status"]
        if status == target:
            return
        if status == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED while waiting for {target}")
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"cluster {name} reaching {target}: the run budget ended first; not graded")
    raise AssertionError(f"cluster {name} did not reach {target} within {timeout_s}s")


def _wait_cluster_gone(eks, name, timeout_s=1200):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"cluster {name} was not removed within {timeout_s}s")


def _create_active_eks_cluster(ctx):
    eks = ctx.client("eks")
    role_arn = _create_eks_cluster_role(ctx)
    subnet_ids = _create_eks_vpc_subnets(ctx)
    name = ctx.unique_name("sim2real-eks-clu-")
    # CreateCluster answers InvalidParameterException until the new role propagates to EKS.
    create_deadline = time.monotonic() + _budget_s(ctx, 120.0)
    while True:
        try:
            eks.create_cluster(name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnet_ids})
            break
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidParameterException":
                raise
            if time.monotonic() >= create_deadline:
                if _budget_spent(ctx):
                    raise TimeoutError("creating the cluster while its new role propagates: the run budget ended first; not graded") from e
                raise
            time.sleep(2)

    def _cleanup():
        # DeleteCluster answers ResourceInUseException while the update an insights refresh leaves
        # behind is in progress; retry it for up to 1200 s, then wait for the cluster to go.
        deadline = time.monotonic() + 1200
        while True:
            try:
                eks.delete_cluster(name=name)
                break
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code != "ResourceInUseException" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)
        _wait_cluster_gone(eks, name)

    ctx.on_cleanup(_cleanup)
    _wait_cluster_status(ctx, eks, name, "ACTIVE")
    return name


# AWS-managed ENIs in this VPC delete asynchronously, so DeleteSubnet / DeleteSecurityGroup /
# DeleteVpc fail DependencyViolation while they remain: retry that code inside one window shared
# by the network deletes, then raise naming the ENIs still attached.
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
        _time.sleep(10)
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
        _time.sleep(10)


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
