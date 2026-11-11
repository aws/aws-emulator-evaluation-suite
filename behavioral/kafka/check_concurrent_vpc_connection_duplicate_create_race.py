"""concurrent-vpc-connection-duplicate-create-race."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-vpc-connection-duplicate-create-race"
GROUP = "concurrency"
SERVICES = ["kafka"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two simultaneous, identical CreateVpcConnection calls both succeed with distinct VpcConnectionArns and
    both appear in ListClientVpcConnections: the API has no idempotency token, so neither call may fail or be
    merged."""
    kafka = ctx.client("kafka")
    cluster_arn = _create_vpc_connectivity_cluster(ctx, "sim2real-vpcrace")

    client_vpc_id, client_subnets = _pick_subnets(ctx, 3)
    client_sg = _create_security_group(ctx, client_vpc_id, ctx.unique_name("sim2real-vpcrace-client-sg-"))

    def _create():
        return _call_capture(
            lambda: kafka.create_vpc_connection(
                TargetClusterArn=cluster_arn,
                Authentication="SASL_IAM",
                VpcId=client_vpc_id,
                ClientSubnets=client_subnets,
                SecurityGroups=[client_sg],
            )
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_create) for _ in range(2)]
        results = [f.result() for f in futures]

    oks = [r for r in results if r[0] == "ok"]
    assert len(oks) == 2, f"expected both concurrent CreateVpcConnection calls to succeed independently, got {results}"

    arns = [r[1]["VpcConnectionArn"] for r in oks]
    ctx.on_cleanup(lambda: _delete_vpc_connections(kafka, arns))
    assert len(set(arns)) == 2, f"expected two distinct VpcConnectionArns, got {arns}"

    listed = kafka.list_client_vpc_connections(ClusterArn=cluster_arn).get("ClientVpcConnections", [])
    listed_arns = {c["VpcConnectionArn"] for c in listed if "VpcConnectionArn" in c}
    for arn in arns:
        assert arn in listed_arns, f"connection {arn} missing from ListClientVpcConnections: {listed}"


def _call_capture(fn):
    from botocore.exceptions import ClientError

    try:
        return ("ok", fn())
    except ClientError as e:
        return ("error", e.response["Error"]["Code"])


# DeleteVpcConnection is refused while a connection is still CREATING: "This operation is only
# valid for resources that are in one of the following states :[AVAILABLE, FAILED, INACTIVE,
# REJECTED]". The client security group cannot go until the connection's
# ENIs have left the client subnets, so the delete also waits until the connection is gone.
_VPC_CONNECTION_DELETABLE = ("AVAILABLE", "FAILED", "INACTIVE", "REJECTED")


def _delete_vpc_connections(kafka, arns, timeout_s: float = 1000.0, interval_s: float = 15.0) -> None:
    """Delete every connection once deletable, in parallel, then wait until all are gone.

    The client security group cannot go while their ENIs remain. One deadline bounds both phases
    so the whole teardown fits the 1800 s cleanup budget; a connection still present then raises."""
    deadline = time.monotonic() + timeout_s
    pending, state = list(arns), {}
    while pending and time.monotonic() < deadline:
        for arn in list(pending):
            try:
                state[arn] = kafka.describe_vpc_connection(Arn=arn).get("State")
            except kafka.exceptions.NotFoundException:
                pending.remove(arn)
                continue
            if state[arn] in _VPC_CONNECTION_DELETABLE:
                kafka.delete_vpc_connection(Arn=arn)
                pending.remove(arn)
            elif state[arn] in ("DELETING", "DEACTIVATING"):
                pending.remove(arn)
        if pending:
            time.sleep(interval_s)
    if pending:
        raise AssertionError(f"VPC connections {pending} never reached a deletable state (last {state})")
    remaining = list(arns)
    while remaining and time.monotonic() < deadline:
        for arn in list(remaining):
            try:
                kafka.describe_vpc_connection(Arn=arn)
            except kafka.exceptions.NotFoundException:
                remaining.remove(arn)
        if remaining:
            time.sleep(interval_s)
    if remaining:
        raise AssertionError(f"VPC connections {remaining} still present {timeout_s}s into their teardown")


def _delete_security_group(ec2, sg_id: str, timeout_s: float = 600.0) -> None:
    """Retries while ENIs of the cluster or a VPC connection still hold the group, then raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(2.0)


def _pick_kafka_version(ctx) -> str:
    """Express brokers support only Apache Kafka versions 3.8.x, 3.9.x.kraft and 4.2.x.kraft."""
    status = {v["Version"]: v.get("Status") for v in ctx.client("kafka").list_kafka_versions().get("KafkaVersions", [])}
    if status.get("3.8.x") != "ACTIVE":
        raise AssertionError(f"Kafka 3.8.x is not ACTIVE in ListKafkaVersions: {sorted(status)}")
    return "3.8.x"


def _pick_subnets(ctx, count: int):
    """The run's network (ctx.network()) and `count` of its subnets in distinct AZs."""
    net = ctx.network()
    zones = net.availability_zones
    if len(zones) < count:
        raise AssertionError(f"the run's network has subnets in {len(zones)} AZs, need {count}")
    return net.vpc_id, [net.subnets[az] for az in zones][:count]


def _create_security_group(ctx, vpc_id: str, name: str) -> str:
    """A group with no ingress rule: the check never opens a connection to the cluster."""
    ec2 = ctx.client("ec2")
    sg_id = ec2.create_security_group(
        GroupName=name,
        Description="sim2real kafka behavioral check",
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["GroupId"]

    ctx.on_cleanup(lambda: _delete_security_group(ec2, sg_id))
    return sg_id


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_cluster_active(ctx, cluster_arn: str, timeout_s: float = 3600.0, interval_s: float = 2.0):
    # Measured, not documented: a 3-broker Express cluster across 3 AZs can exceed 1800s.
    kafka = ctx.client("kafka")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        info = kafka.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]
        state = info.get("State")
        if state == "ACTIVE":
            return info
        if state == "FAILED":
            raise AssertionError(f"cluster {cluster_arn} entered FAILED state: {info}")
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"cluster {cluster_arn} reaching ACTIVE: the run budget ended first; not graded")
    raise AssertionError(f"cluster {cluster_arn} did not reach ACTIVE within {timeout_s}s")


def _enable_multi_vpc(ctx, cluster_arn: str, timeout_s: float = 4800.0, interval_s: float = 2.0) -> None:
    """Turn on multi-VPC private connectivity (IAM auth scheme) for an ACTIVE cluster.

    CreateClusterV2 rejects VpcConnectivity auth schemes at creation, so it is enabled here via
    UpdateConnectivity, a rolling broker reboot that can run over 50 minutes (4800s ceiling).
    """
    kafka = ctx.client("kafka")
    current_version = kafka.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]["CurrentVersion"]
    resp = kafka.update_connectivity(
        ClusterArn=cluster_arn,
        CurrentVersion=current_version,
        ConnectivityInfo={"VpcConnectivity": {"ClientAuthentication": {"Sasl": {"Iam": {"Enabled": True}}}}},
    )
    op_arn = resp["ClusterOperationArn"]
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        info = kafka.describe_cluster_operation_v2(ClusterOperationArn=op_arn)["ClusterOperationInfo"]
        state = info.get("OperationState", "")
        if state == "UPDATE_COMPLETE":
            return
        if state in ("UPDATE_FAILED", "FAILED"):
            raise AssertionError(f"UpdateConnectivity {op_arn} ended {state}: {info.get('ErrorInfo')}")
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"UpdateConnectivity {op_arn} completing: the run budget ended first; not graded")
    raise AssertionError(f"UpdateConnectivity {op_arn} did not complete within {timeout_s}s")


def _create_vpc_connectivity_cluster(ctx, name_prefix: str) -> str:
    """An IAM-authenticated cluster with multi-VPC private connectivity enabled, the minimum a
    target needs to accept CreateVpcConnection (unauthenticated clusters are unsupported, and IAM
    avoids the KMS/Secrets Manager setup SASL/SCRAM needs)."""
    kafka = ctx.client("kafka")
    version = _pick_kafka_version(ctx)
    vpc_id, subnets = _pick_subnets(ctx, 3)
    sg_id = _create_security_group(ctx, vpc_id, ctx.unique_name(f"{name_prefix}-sg-"))

    cluster_name = ctx.unique_name(f"{name_prefix}-")
    cluster_arn = kafka.create_cluster_v2(
        ClusterName=cluster_name,
        Provisioned={
            "KafkaVersion": version,
            "NumberOfBrokerNodes": 3,
            "ClientAuthentication": {"Sasl": {"Iam": {"Enabled": True}}},
            "EncryptionInfo": {"EncryptionInTransit": {"ClientBroker": "TLS", "InCluster": True}},
            "BrokerNodeGroupInfo": {
                "InstanceType": "express.m7g.large",
                "ClientSubnets": subnets,
                "SecurityGroups": [sg_id],
            },
        },
        Tags={"sim2real:managed": "true"},
    )["ClusterArn"]

    def _cleanup():
        # Waits until the cluster is gone, so the security group delete after it can succeed.
        try:
            kafka.delete_cluster(ClusterArn=cluster_arn)
        except kafka.exceptions.NotFoundException:
            return
        deadline = time.monotonic() + 900.0
        while time.monotonic() < deadline:
            try:
                kafka.describe_cluster_v2(ClusterArn=cluster_arn)
            except kafka.exceptions.NotFoundException:
                return
            time.sleep(2.0)
        raise AssertionError(f"cluster {cluster_arn} still present 900s after DeleteCluster")

    ctx.on_cleanup(_cleanup)
    _wait_cluster_active(ctx, cluster_arn)
    _enable_multi_vpc(ctx, cluster_arn)
    return cluster_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
