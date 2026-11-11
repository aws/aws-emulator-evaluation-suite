"""insights-refresh-lifecycle-transitions."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "insights-refresh-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartInsightsRefresh returns IN_PROGRESS and DescribeInsightsRefresh then reaches COMPLETED
    on a healthy new cluster, with endedAt not before startedAt (API_DescribeInsightsRefresh)."""
    eks = ctx.client("eks")
    cluster = _ensure_active_cluster(ctx)
    name = cluster["name"]

    start_resp = _start_insights_refresh_when_ready(ctx, name)
    assert start_resp["status"] == "IN_PROGRESS", start_resp

    final = _wait_insights_refresh_terminal(ctx, name)
    assert final["status"] == "COMPLETED", f"insights refresh ended in {final}"
    assert "startedAt" in final and "endedAt" in final, f"missing timestamps in terminal response: {final}"
    assert final["endedAt"] >= final["startedAt"], (
        f"endedAt {final['endedAt']} precedes startedAt {final['startedAt']}: {final}"
    )


# ===== helpers =====

def _start_insights_refresh_when_ready(ctx, cluster_name: str, timeout_s: float = 1100.0):
    from botocore.exceptions import ClientError

    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return eks.start_insights_refresh(clusterName=cluster_name)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidRequestException" and "already in progress" in str(exc).lower():
                # EKS's own scheduled first refresh is still running; issue ours once it clears.
                last_err = exc
                time.sleep(2)
                continue
            if code != "ResourceNotFoundException":
                raise
            # ACTIVE does not imply cluster insights are queryable yet: real AWS
            # 404s StartInsightsRefresh with "isn't available yet for cluster
            # insights. Wait up to 15 minutes and try again." right after create.
            last_err = exc
            time.sleep(2)
    raise AssertionError(
        f"cluster {cluster_name} never became available for cluster insights within "
        f"{timeout_s}s: {last_err}"
    )


def _wait_insights_refresh_terminal(ctx, cluster_name: str, timeout_s: float = 600.0):
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    desc: dict[str, Any] = {}
    while time.monotonic() < deadline:
        desc = _read_refresh(eks, cluster_name)
        if desc["status"] in ("COMPLETED", "FAILED"):
            return desc
        time.sleep(2)
    raise AssertionError(f"insights refresh for {cluster_name} never reached a terminal state: {desc}")


def _ensure_active_cluster(ctx) -> dict[str, str]:
    import json

    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    eks = ctx.client("eks")

    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup_role():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup_role)

    subnet_ids = _create_network(ctx)

    cluster_name = ctx.unique_name("sim2real-eks-")
    # The just-created role is rejected (InvalidParameterException) until IAM propagates it:
    # retry every 2 s up to 80 s, capped by the run's remaining time.
    retry_deadline = time.monotonic() + 80.0
    left = ctx.time_left()
    if left is not None:
        retry_deadline = min(retry_deadline, time.monotonic() + max(1.0, left - 5.0))
    while True:
        try:
            eks.create_cluster(
                name=cluster_name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterException" or time.monotonic() >= retry_deadline:
                raise
        time.sleep(2)

    def _cleanup_cluster():
        try:
            eks.delete_cluster(name=cluster_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        deadline = time.monotonic() + 15 * 60
        while time.monotonic() < deadline:
            try:
                eks.describe_cluster(name=cluster_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                    return
                raise
            time.sleep(2)

    ctx.on_cleanup(_cleanup_cluster)

    deadline = time.monotonic() + 25 * 60
    desc: dict[str, Any] = {}
    while time.monotonic() < deadline:
        desc = eks.describe_cluster(name=cluster_name)["cluster"]
        if desc["status"] == "ACTIVE":
            return {"name": cluster_name, "arn": desc["arn"], "role_arn": role_arn, "version": desc["version"]}
        if desc["status"] == "FAILED":
            raise AssertionError(f"cluster {cluster_name} entered FAILED state while creating: {desc}")
        time.sleep(2)
    raise AssertionError(f"cluster {cluster_name} did not become ACTIVE within timeout: {desc}")


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
        time.sleep(2)
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
        time.sleep(2)


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
