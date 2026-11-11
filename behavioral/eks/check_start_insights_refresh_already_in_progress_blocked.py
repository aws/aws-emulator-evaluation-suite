"""start-insights-refresh-already-in-progress-blocked."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-insights-refresh-already-in-progress-blocked"
GROUP = "overly-permissive"
SERVICES = ["eks"]

_IN_PROGRESS_RE = re.compile(
    re.escape("Another refresh operation is already in progress for the cluster. "
              "(Service: EksClusterInsights, Status Code: 409, Request ID: ")
    + r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    + re.escape(") (SDK Attempt Count: 1)")
)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartInsightsRefresh is single-flight per cluster: a second call during an IN_PROGRESS refresh
    is rejected with InvalidRequestException and leaves its startedAt untouched; once the first refresh
    is terminal, a new one is accepted."""
    eks = ctx.client("eks")
    subnet_ids = _provision_subnets(ctx)
    role_arn = _create_role(ctx, "eks.amazonaws.com", ["AmazonEKSClusterPolicy"])

    cluster_name = ctx.unique_name("sim2real-eks-insq-")
    _create_cluster_with_retry(ctx, eks, cluster_name, role_arn, subnet_ids)
    ctx.on_cleanup(lambda: _safe_delete_cluster(ctx, eks, cluster_name))
    _wait_cluster_status(ctx, eks, cluster_name, "ACTIVE", timeout_s=1500)

    # The check opens the in-progress window itself: it starts a refresh and issues the
    # second StartInsightsRefresh immediately, inside the window its own call created.
    started = _start_own_insights_refresh(ctx, eks, cluster_name, timeout_s=900)
    assert started["status"] == "IN_PROGRESS", f"StartInsightsRefresh response -> {started!r}"
    assert started["message"] == "Initiated cluster insights refresh.", f"StartInsightsRefresh response -> {started!r}"

    # Negative: a second StartInsightsRefresh while the first is still running is
    # rejected, not queued and not run concurrently.
    code, msg = _expect_error(lambda: eks.start_insights_refresh(clusterName=cluster_name))
    assert code == "InvalidRequestException", f"second refresh while one runs -> {code}: {msg}"
    # message varies: it carries the request id of EKS's internal insights call, so the
    # whole string is matched with only that id left open.
    assert _IN_PROGRESS_RE.fullmatch(msg), f"second refresh while one runs -> {msg!r}"

    first = eks.describe_insights_refresh(clusterName=cluster_name)
    assert first["status"] == "IN_PROGRESS", f"expected the first refresh to be IN_PROGRESS, got {first['status']!r}"
    started_at = first["startedAt"]
    assert started_at is not None, "expected the first refresh to report a non-null startedAt"

    # Effect absent: the original refresh's startedAt is unchanged -- the rejected call
    # did not reset or restart it.
    still = eks.describe_insights_refresh(clusterName=cluster_name)
    assert still["startedAt"] == started_at, "the in-progress refresh's startedAt changed after a rejected second start"

    # Positive control: once the first refresh reaches a terminal state, starting a new
    # one is accepted normally.
    terminal_status, _, _ = _wait_insights_refresh_terminal(ctx, eks, cluster_name, timeout_s=900)
    assert terminal_status == "COMPLETED", f"the first refresh ended {terminal_status!r}"
    done = eks.describe_insights_refresh(clusterName=cluster_name)
    assert done["message"] == "Cluster insights refresh has completed successfully.", done

    restarted = eks.start_insights_refresh(clusterName=cluster_name)
    assert restarted["status"] == "IN_PROGRESS", f"follow-up StartInsightsRefresh response -> {restarted!r}"
    assert restarted["message"] == "Initiated cluster insights refresh.", f"follow-up StartInsightsRefresh response -> {restarted!r}"
    second = eks.describe_insights_refresh(clusterName=cluster_name)
    assert second["status"] == "IN_PROGRESS", f"expected the follow-up refresh to start IN_PROGRESS, got {second['status']!r}"
    assert second["startedAt"] != started_at, "the follow-up refresh did not record a fresh startedAt"
    second_status, _, _ = _wait_insights_refresh_terminal(ctx, eks, cluster_name, timeout_s=900)
    assert second_status == "COMPLETED", f"the follow-up refresh ended {second_status!r}"


# ===== helpers =====

def _expect_error(fn):
    """Call fn(), require that it raises, return (ErrorCode, Message)."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _provision_subnets(ctx) -> list[str]:
    """Two subnets in distinct AZs, in a VPC this check creates for its test cluster."""
    ec2 = ctx.client("ec2")
    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
    az_names = sorted(a["ZoneName"] for a in azs)[:2]
    if len(az_names) < 2:
        raise AssertionError("region does not have at least 2 available availability zones")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.78.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real-check", "Value": CHECK}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))

    subnet_ids = []
    for i, az in enumerate(az_names):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.78.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "sim2real-check", "Value": CHECK}]}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _retry_delete(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _retry_delete(fn, attempts: int = 20, delay_s: float = 15.0) -> None:
    for i in range(attempts):
        try:
            fn()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if "NotFound" in code:
                return
            if i == attempts - 1:
                raise
            time.sleep(delay_s)


def _create_role(ctx, service_principal: str, managed_policy_names: list[str]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": service_principal}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_delete_role(ctx, role_name, managed_policy_names))
    for policy_name in managed_policy_names:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=f"arn:aws:iam::aws:policy/{policy_name}")
    return role_arn


def _safe_delete_role(ctx, role_name: str, managed_policy_names: list[str]) -> None:
    iam = ctx.client("iam")
    for policy_name in managed_policy_names:
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=f"arn:aws:iam::aws:policy/{policy_name}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_cluster_with_retry(ctx, eks, name: str, role_arn: str, subnet_ids: list[str], timeout_s: float = 180.0) -> None:
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            eks.create_cluster(
                name=name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
                tags={"sim2real-check": CHECK},
            )
            return
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
            if last_code == "ClientException":
                time.sleep(2)
                continue
            raise
    if _budget_spent(ctx):
        raise TimeoutError(f"creating cluster {name} while its role propagates: the run budget ended first; not graded")
    raise AssertionError(f"CreateCluster kept failing with {last_code} after {timeout_s}s (IAM role propagation?)")


def _wait_cluster_status(ctx, eks, name: str, want: str, timeout_s: float, interval_s: float = 2.0) -> None:
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = eks.describe_cluster(name=name)["cluster"]["status"]
        if last == want:
            return
        if last == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED while waiting for {want}")
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"cluster {name} reaching {want}: the run budget ended first; not graded")
    raise AssertionError(f"cluster {name} did not reach {want} within {timeout_s}s (last={last})")


def _wait_cluster_gone(ctx, eks, name: str, timeout_s: float, interval_s: float = 15.0) -> None:
    # Unlike _expect_error (which asserts a call is REJECTED), success here is the expected
    # transient state while deletion is still in flight -- only a specific not-found code ends
    # the wait, so this polls directly rather than through the strict assertion helper.
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} was not deleted within {timeout_s}s")


def _safe_delete_cluster(ctx, eks, name: str) -> None:
    try:
        eks.delete_cluster(name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    _wait_cluster_gone(ctx, eks, name, timeout_s=900)


def _start_own_insights_refresh(ctx, eks, cluster_name: str, timeout_s: float, interval_s: float = 2.0) -> dict:
    """Start a refresh this check owns and return the StartInsightsRefresh response.

    Right after a cluster reaches ACTIVE the insights subsystem can still answer
    ResourceNotFoundException ("isn't available yet"), and EKS can run a scheduled refresh of
    its own in that window; retry through both until this check's own refresh starts."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return eks.start_insights_refresh(clusterName=cluster_name)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "").lower()
            if code == "ResourceNotFoundException" and "available yet" in message:
                last_err = err
                time.sleep(interval_s)
                continue
            if code == "InvalidRequestException" and "scheduled" in message:
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    if _budget_spent(ctx):
        raise TimeoutError(f"starting an insights refresh on {cluster_name}: the run budget ended first; not graded")
    raise AssertionError(f"StartInsightsRefresh for {cluster_name} could not start a refresh within {timeout_s}s: {last_err}")


def _wait_insights_refresh_terminal(ctx, eks, cluster_name: str, timeout_s: float, interval_s: float = 2.0):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = eks.describe_insights_refresh(clusterName=cluster_name)
        last_status = resp.get("status")
        if last_status in ("COMPLETED", "FAILED"):
            return last_status, resp.get("startedAt"), resp.get("endedAt")
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"insights refresh for {cluster_name} reaching a terminal state: the run budget ended first; not graded")
    raise AssertionError(f"insights refresh for {cluster_name} did not reach a terminal state within {timeout_s}s (last={last_status})")


def _budget_s(ctx, cap_s: float) -> float:
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s so the wait fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx) -> bool:
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


# EC2 network teardown: a resource in this VPC deletes asynchronously and leaves its ENIs behind for a
# while, so each subnet / security group / VPC delete waits for them and retries DependencyViolation
# to one deadline shared by all of the check's network deletes, then raises naming the ENIs left.
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
