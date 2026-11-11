"""insights-refresh-cooldown-throttle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "insights-refresh-cooldown-throttle"
GROUP = "visibility-timeout-ttl"
SERVICES = ["eks"]

_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
# EKS's own scheduled refresh refusing an explicit start; the asserted refusal shares its code.
_SCHEDULED_REFRESH_RUNNING = "A scheduled cluster insights refresh is already in progress. "


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A StartInsightsRefresh while a refresh is IN_PROGRESS is refused (400 InvalidRequestException, "Another refresh
    operation is already in progress for the cluster.") without restarting it; once that refresh is COMPLETED a new
    one starts and completes with a fresh startedAt."""
    eks = ctx.client("eks")
    cluster = _create_active_eks_cluster(ctx)

    first = _start_insights_refresh_with_retry(ctx, eks, cluster)
    assert first["status"] == "IN_PROGRESS", first
    # Precondition for the claim: the refresh this check just started still holds the
    # in-progress window when the second call is fired immediately afterwards.
    before = _read_refresh(eks, cluster)
    for _ in range(5):
        if before["status"] is not None:
            break
        time.sleep(2)
        before = _read_refresh(eks, cluster)
    assert before["status"] == "IN_PROGRESS", f"the held refresh window closed before the second call: {before}"
    original_started_at = before["startedAt"]

    err, http_status = _client_error(lambda: eks.start_insights_refresh(clusterName=cluster))
    assert err["Code"] == "InvalidRequestException", f"expected throttled second refresh to be rejected, got {err}"
    assert http_status == 400, (http_status, err)
    # The message embeds a backend request id the check never sees; the text around it is graded.
    message = err.get("Message") or ""
    assert message.startswith(
        "Another refresh operation is already in progress for the cluster. "
        "(Service: EksClusterInsights, Status Code: 409, Request ID: "
    ) and message.endswith(") (SDK Attempt Count: 1)"), err

    # effect absent: the in-flight refresh was not restarted by the rejected call
    after_reject = eks.describe_insights_refresh(clusterName=cluster)
    assert after_reject["startedAt"] == original_started_at, (
        "the rejected StartInsightsRefresh call appears to have restarted the refresh's "
        f"startedAt: {original_started_at} -> {after_reject['startedAt']}"
    )

    status = _wait_refresh_terminal(ctx, eks, cluster)
    assert status == "COMPLETED", f"expected the original refresh to complete, got {status}"

    # positive control: once terminal, a new refresh is accepted (cooldown was tied to
    # the in-flight state, not a permanent block)
    second = eks.start_insights_refresh(clusterName=cluster)
    assert second["status"] == "IN_PROGRESS", second
    # An independent read right after the start still sees the new refresh in flight.
    after_second_start = eks.describe_insights_refresh(clusterName=cluster)
    assert after_second_start["status"] == "IN_PROGRESS", (
        f"expected the follow-up refresh to be IN_PROGRESS on an independent read, got {after_second_start}"
    )

    # terminal read: independent of the mutating StartInsightsRefresh call, and proves
    # this is a genuinely new refresh (a fresh startedAt), not the completed original
    # read back stale.
    assert _wait_refresh_terminal(ctx, eks, cluster) == "COMPLETED"
    after_second = eks.describe_insights_refresh(clusterName=cluster)
    assert after_second["status"] == "COMPLETED", after_second
    assert after_second["startedAt"] != original_started_at, (
        "the follow-up refresh did not record a fresh startedAt: "
        f"{after_second['startedAt']} == original {original_started_at}"
    )


def _client_error(fn):
    """Call fn(); return its botocore error (Code and Message) and its HTTP status. An unexpected
    SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"], e.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _start_insights_refresh_with_retry(ctx, eks, cluster, timeout_s=1200, interval_s=2):
    """Right after a cluster reaches ACTIVE, the insights subsystem can lag behind and
    reject StartInsightsRefresh with ResourceNotFoundException ("isn't available yet") for
    up to ~15 minutes; retry through that bounded warm-up window. Separately, EKS can
    autonomously schedule its own insights refresh shortly after the cluster becomes
    available, which races an explicit StartInsightsRefresh and rejects it with
    InvalidRequestException ("already in progress") -- confirmed on real AWS, not assumed.
    Wait that pre-existing refresh out, then issue ours."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return eks.start_insights_refresh(clusterName=cluster)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            message = e.response["Error"].get("Message", "")
            if code == "ResourceNotFoundException" and "isn't available yet" in message:
                last_err = e
                time.sleep(interval_s)
                continue
            if code == "InvalidRequestException" and message.startswith(_SCHEDULED_REFRESH_RUNNING):
                # The autonomous refresh is not always readable through DescribeInsightsRefresh,
                # so wait it out by retrying the start itself.
                last_err = e
                time.sleep(interval_s)
                continue
            raise
    if _budget_spent(ctx):
        raise TimeoutError(f"starting an insights refresh on {cluster}: the run budget ended first; not graded")
    raise AssertionError(f"cluster insights for {cluster} never became available to start a fresh refresh within {timeout_s}s: {last_err}")


def _wait_refresh_terminal(ctx, eks, cluster, timeout_s=900, interval_s=2):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = _read_refresh(eks, cluster)["status"]
        if status in ("COMPLETED", "FAILED"):
            return status
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"refresh for {cluster} reaching a terminal state: the run budget ended first; not graded")
    raise AssertionError(f"refresh for {cluster} did not reach a terminal state within {timeout_s}s")


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s so the wait fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _create_eks_cluster_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real-managed", "Value": "true"}],
    )["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_CLUSTER_POLICY)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=_CLUSTER_POLICY)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _wait_cluster_status(ctx, eks, name, target, timeout_s=1200, interval_s=2):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = eks.describe_cluster(name=name)["cluster"]["status"]
        if status == target:
            return
        if status == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED while waiting for {target}")
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"cluster {name} reaching {target}: the run budget ended first; not graded")
    raise AssertionError(f"cluster {name} did not reach {target} within {timeout_s}s")


def _wait_cluster_gone(eks, name, timeout_s=1200, interval_s=20):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} was not removed within {timeout_s}s")


def _create_cluster_with_retry(ctx, eks, name, role_arn, subnet_ids, timeout_s=180, interval_s=2):
    """Right after AssumeRolePolicyDocument is attached, EKS can reject CreateCluster because
    the trust policy has not yet propagated; retry through that bounded window instead of
    guessing a fixed sleep."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            eks.create_cluster(
                name=name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
                tags={"sim2real-managed": "true"},
            )
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("ClientException", "InvalidParameterException"):
                last_err = e
                time.sleep(interval_s)
                continue
            raise
    if _budget_spent(ctx):
        raise TimeoutError(f"creating cluster {name} while its role propagates: the run budget ended first; not graded")
    raise AssertionError(f"CreateCluster for {name} kept failing with {last_err} after {timeout_s}s (IAM role propagation?)")


def _create_active_eks_cluster(ctx):
    eks = ctx.client("eks")
    role_arn = _create_eks_cluster_role(ctx)
    subnet_ids = _create_network(ctx)
    name = ctx.unique_name("sim2real-eks-clu-")
    _create_cluster_with_retry(ctx, eks, name, role_arn, subnet_ids)

    def _cleanup():
        # DeleteCluster refuses with ResourceInUseException while an update (such as an
        # insights refresh) is in progress; retry inside a bounded window.
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
                time.sleep(20)
        _wait_cluster_gone(eks, name)

    ctx.on_cleanup(_cleanup)
    _wait_cluster_status(ctx, eks, name, "ACTIVE")
    return name


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
