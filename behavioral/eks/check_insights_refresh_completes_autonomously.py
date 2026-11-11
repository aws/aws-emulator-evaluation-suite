"""insights-refresh-completes-autonomously."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "insights-refresh-completes-autonomously"
GROUP = "server-side"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An insights refresh completes without being polled: after a polled refresh reaches COMPLETED, a second
    StartInsightsRefresh read once after 3x the measured latency is COMPLETED, ended after it started and started
    after the first one ended, so the service runs the refresh on its own."""
    eks = ctx.client("eks")
    cluster = _create_active_cluster(ctx)

    # Positive control: prove the account/cluster can complete an insights refresh at
    # all (so the check can't pass merely because the operation is never reachable),
    # and measure the real completion latency on this wiring.
    control_start = _start_insights_refresh_when_ready(ctx, eks, cluster["name"])
    assert control_start["status"] == "IN_PROGRESS", f"expected IN_PROGRESS, got {control_start}"
    t0 = time.monotonic()
    control = _poll_until(
        ctx,
        lambda: _read_refresh(eks, cluster["name"]),
        lambda r: r["status"] in ("COMPLETED", "FAILED"),
        timeout_s=600.0,
    )
    measured_latency_s = time.monotonic() - t0
    assert control["status"] == "COMPLETED", f"positive-control refresh did not complete: {control}"
    # startedAt/endedAt have whole-second resolution: start the second refresh in a later second
    # than the first one ended, so a new operation always reads startedAt > endedAt.
    time.sleep(1.1)

    # The assertion under test: a second refresh is read once, late, with no polling in between; the
    # wait is 3x the positive control's measured latency (at least 5 s), within the run's remaining time.
    second_start = _start_insights_refresh_when_ready(ctx, eks, cluster["name"])
    assert second_start["status"] == "IN_PROGRESS", f"expected IN_PROGRESS, got {second_start}"
    hold_s = max(5.0, measured_latency_s * 3.0)
    wait_s = _budget_s(ctx, hold_s)
    time.sleep(wait_s)  # the refresh runs unread: no DescribeInsightsRefresh until the hold ends

    refresh = eks.describe_insights_refresh(clusterName=cluster["name"])
    if refresh["status"] == "IN_PROGRESS" and wait_s < hold_s:
        raise TimeoutError("the unpolled wait for the second refresh: the run budget ended first; not graded")
    assert refresh["status"] == "COMPLETED", refresh
    assert refresh["endedAt"] >= refresh["startedAt"], refresh
    assert refresh["startedAt"] > control["endedAt"], (
        f"expected the second refresh to be a genuinely new operation rather than "
        f"the first one echoed back: second startedAt={refresh['startedAt']} is not "
        f"after first endedAt={control['endedAt']}"
    )


def _start_insights_refresh_when_ready(ctx, eks, cluster_name, timeout_s=1200.0):
    """StartInsightsRefresh can be transiently unavailable for two real, observed
    reasons: a just-ACTIVE cluster's insights subsystem lags cluster ACTIVE by up to
    the ~15 minutes AWS's own ResourceNotFoundException message states, and EKS also
    runs its own autonomous "scheduled" refresh that can already occupy the slot
    (InvalidRequestException). Retry the START call on a bounded deadline for both
    rather than assuming either condition away."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return eks.start_insights_refresh(clusterName=cluster_name)
        except eks.exceptions.ResourceNotFoundException as exc:
            last_exc = exc
            time.sleep(2)
        except eks.exceptions.InvalidRequestException as exc:
            if "already in progress" not in str(exc):
                raise
            last_exc = exc
            time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError("starting an insights refresh: the run budget ended first; not graded")
    raise AssertionError(f"could not start an insights refresh within {timeout_s}s: {last_exc}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, *, timeout_s=900.0):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"waiting on {last}: the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s}s, last observed: {last}")


def _create_cluster_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-clusterrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["Role"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _create_active_cluster(ctx, extra_kwargs=None):
    eks = ctx.client("eks")
    name = ctx.unique_name("sim2real-eks-")
    subnet_ids = _create_network(ctx)
    role_arn = _create_cluster_role(ctx)
    kwargs = dict(
        name=name,
        roleArn=role_arn,
        resourcesVpcConfig={"subnetIds": subnet_ids},
        tags={"sim2real": "behavioral"},
    )
    if extra_kwargs:
        kwargs.update(extra_kwargs)

    # A freshly created role can take a few seconds to propagate through IAM; retry the create call
    # on its propagation error until a bounded deadline.
    deadline = time.monotonic() + _budget_s(ctx, 90.0)
    resp = None
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = eks.create_cluster(**kwargs)
            break
        except Exception as exc:  # noqa: BLE001 - retry while the new role propagates
            last_exc = exc
            time.sleep(2)
    if resp is None:
        if _budget_spent(ctx):
            raise TimeoutError("creating the cluster while its new role propagates: the run budget ended first; not graded") from last_exc
        raise last_exc

    ctx.on_cleanup(lambda: _delete_cluster_and_wait(eks, name))
    cluster = _poll_until(
        ctx,
        lambda: eks.describe_cluster(name=name)["cluster"],
        lambda c: c["status"] in ("ACTIVE", "FAILED"),
        timeout_s=1200.0,
    )
    if cluster["status"] != "ACTIVE":
        raise AssertionError(f"cluster did not reach ACTIVE: {cluster['status']}")
    return {"name": name, "arn": cluster["arn"], "role_arn": role_arn, "subnet_ids": subnet_ids}


def _delete_cluster_and_wait(eks, name, timeout_s=1200.0):
    # An insights refresh can leave the cluster with an update in progress, which makes
    # DeleteCluster refuse with ResourceInUseException; retry inside the same window.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            eks.delete_cluster(name=name)
            break
        except eks.exceptions.ResourceNotFoundException:
            return
        except eks.exceptions.ResourceInUseException:
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except eks.exceptions.ResourceNotFoundException:
            return
        time.sleep(2)
    raise AssertionError(f"cluster {name} still exists {timeout_s}s after DeleteCluster")


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _create_network(ctx) -> list[str]:
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.42.0.0/16",
        TagSpecifications=[_tag_spec("vpc", ctx.unique_name("sim2real-eks-vpc-"))],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

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
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    return subnet_ids


# EC2 network teardown waits (bounded) for the cluster's AWS-managed ENIs to leave the subnet
# before it deletes, retries DependencyViolation inside the same window, and raises a final
# failure naming the ENIs. Teardown-only: nothing run() executes calls this.
_NET_TEARDOWN_S = 1260.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    from botocore.exceptions import ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and time.monotonic() < deadline:
        time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except ClientError:
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
