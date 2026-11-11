"""concurrent-vpc-connection-create-same-endpoint-race."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-vpc-connection-create-same-endpoint-race"
GROUP = "concurrency"
SERVICES = ["kafka"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent identical CreateVpcConnection calls are both honored: each gets a unique
    VpcConnectionArn and is independently describable, because the API has no idempotency token.
    """
    kafka = ctx.client("kafka")
    vpc_id, subnet_ids, sg_id = _default_vpc_subnets(ctx)
    cluster_arn = _create_iam_auth_cluster(ctx, subnet_ids, sg_id)

    def _create():
        return kafka.create_vpc_connection(
            TargetClusterArn=cluster_arn,
            Authentication="SASL_IAM",
            VpcId=vpc_id,
            ClientSubnets=subnet_ids,
            SecurityGroups=[sg_id],
            Tags={"sim2real:managed": "true"},
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_create) for _ in range(2)]
        results = []
        errors = []
        for f in futures:
            try:
                results.append(f.result())
            except ClientError as e:
                errors.append(e.response["Error"]["Code"])

    for r in results:
        arn = r["VpcConnectionArn"]
        ctx.on_cleanup(lambda arn=arn: _delete_vpc_connection(ctx, arn))

    # Both racers must be honored: neither silently dropped nor merged into the other.
    assert len(results) == 2, f"expected both concurrent creates to succeed, got {len(results)} (errors={errors})"
    arns = {r["VpcConnectionArn"] for r in results}
    assert len(arns) == 2, "the two concurrent creates must not collapse onto the same ARN"

    for r in results:
        info = _wait_vpc_connection_state(ctx, r["VpcConnectionArn"], {"AVAILABLE", "CREATING"}, timeout_s=900)
        assert info["VpcId"] == vpc_id, f"expected VpcId={vpc_id}, got {info['VpcId']} for {r['VpcConnectionArn']}"
        assert sorted(info["Subnets"]) == sorted(subnet_ids), (
            f"expected subnets {sorted(subnet_ids)}, got {sorted(info['Subnets'])} for {r['VpcConnectionArn']}"
        )
        assert info["TargetClusterArn"] == cluster_arn, (
            f"expected TargetClusterArn={cluster_arn}, got {info['TargetClusterArn']} for {r['VpcConnectionArn']}"
        )

    # Independent read at the destination's own listing, not just each connection's own describe:
    # both ARNs must be visible with no merge/duplication/omission.
    listed = kafka.list_client_vpc_connections(ClusterArn=cluster_arn).get("ClientVpcConnections", [])
    listed_arns = [c["VpcConnectionArn"] for c in listed if "VpcConnectionArn" in c]
    for arn in arns:
        assert listed_arns.count(arn) == 1, (
            f"expected {arn} exactly once in ListClientVpcConnections, got {listed_arns.count(arn)} in {listed_arns}"
        )



def _default_vpc_subnets(ctx, min_count: int = 2):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())[:2]
    if len(subnet_ids) < 2:
        raise AssertionError("fewer than 2 AZ subnets available in the VPC to place MSK brokers")
    sgs = ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["SecurityGroups"]
    return vpc_id, subnet_ids, sgs[0]["GroupId"]


def _pick_kafka_version(kafka) -> str:
    versions = kafka.list_kafka_versions().get("KafkaVersions", [])
    if not versions:
        raise AssertionError("no Kafka versions returned by ListKafkaVersions")
    active = [v["Version"] for v in versions if v.get("Status") == "ACTIVE"]
    if "3.9.x" in active:  # recommended, still ZooKeeper; older Standard versions are refused
        return "3.9.x"
    return active[0] if active else versions[-1]["Version"]


def _create_iam_auth_cluster(ctx, subnet_ids, sg_id) -> str:
    kafka = ctx.client("kafka")
    name = ctx.unique_name("sim2real-vpcrace-")
    version = _pick_kafka_version(kafka)
    resp = kafka.create_cluster(
        ClusterName=name,
        KafkaVersion=version,
        NumberOfBrokerNodes=len(subnet_ids),
        BrokerNodeGroupInfo={
            # Multi-VPC private connectivity does not support kafka.t3.small (AWS docs,
            # "Requirements and limitations for multi-VPC private connectivity").
            "InstanceType": "kafka.m5.large",
            "ClientSubnets": subnet_ids,
            "SecurityGroups": [sg_id],
        },
        ClientAuthentication={"Sasl": {"Iam": {"Enabled": True}}},
        EncryptionInfo={"EncryptionInTransit": {"ClientBroker": "TLS", "InCluster": True}},
        Tags={"sim2real:managed": "true"},
    )
    arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster(ctx, arn))
    # A 2-broker cluster create can exceed 1800s on real AWS.
    info = _wait_cluster_state(ctx, arn, {"ACTIVE"}, timeout_s=2700)

    # Real MSK rejects VpcConnectivity auth schemes enabled at CreateCluster time
    # ("all vpcConnectivity auth schemes must be disabled") -- multi-VPC connectivity auth can
    # only be turned on afterward, via UpdateConnectivity against an ACTIVE cluster.
    op = kafka.update_connectivity(
        ClusterArn=arn,
        CurrentVersion=info["CurrentVersion"],
        ConnectivityInfo={
            "VpcConnectivity": {"ClientAuthentication": {"Sasl": {"Iam": {"Enabled": True}}}},
        },
    )
    # A 2-broker UPDATE_CONNECTIVITY can run over 50 minutes on real AWS; 4800s leaves headroom.
    final_op = _wait_operation_state(
        ctx, op["ClusterOperationArn"], {"UPDATE_COMPLETE", "UPDATE_FAILED"}, timeout_s=4800
    )
    assert final_op["OperationState"] == "UPDATE_COMPLETE", (
        f"enabling multi-VPC connectivity auth did not complete: {final_op}"
    )
    _wait_cluster_state(ctx, arn, {"ACTIVE"}, timeout_s=1800)
    return arn


def _delete_cluster(ctx, arn: str) -> None:
    kafka = ctx.client("kafka")
    try:
        _wait_until_deletable(kafka, arn)
        kafka.delete_cluster(ClusterArn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NotFoundException":
            return
        raise
    _wait_cluster_deleted(ctx, arn, timeout_s=1800)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_cluster_state(ctx, arn, target_states, timeout_s=1800.0, interval_s=2.0):
    kafka = ctx.client("kafka")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        info = kafka.describe_cluster(ClusterArn=arn)["ClusterInfo"]
        last = info["State"]
        if last in target_states:
            return info
        if last == "FAILED":
            raise AssertionError(f"cluster entered FAILED state while waiting for {target_states}")
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"cluster {arn} reaching {target_states}: the run budget ended first; not graded")
    raise AssertionError(f"cluster did not reach {target_states} within {timeout_s}s (last={last})")


def _wait_operation_state(ctx, op_arn, target_states, timeout_s=1800.0, interval_s=2.0):
    kafka = ctx.client("kafka")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = kafka.describe_cluster_operation(ClusterOperationArn=op_arn)["ClusterOperationInfo"]
        if last["OperationState"] in target_states:
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"cluster operation {op_arn} reaching {target_states}: the run budget ended first; not graded")
    raise AssertionError(f"cluster operation did not reach {target_states} within {timeout_s}s (last={last})")


def _wait_cluster_deleted(ctx, arn, timeout_s=1800.0, interval_s=20.0):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            kafka.describe_cluster(ClusterArn=arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError("cluster did not delete within timeout")


def _delete_vpc_connection(ctx, arn: str) -> None:
    kafka = ctx.client("kafka")
    _wait_vpc_connection_deletable(kafka, arn)
    try:
        kafka.delete_vpc_connection(Arn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NotFoundException":
            return
        raise


def _wait_vpc_connection_state(ctx, arn, target_states, timeout_s=900.0, interval_s=2.0):
    kafka = ctx.client("kafka")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        info = kafka.describe_vpc_connection(Arn=arn)
        last = info["State"]
        if last in target_states:
            return info
        if last in {"FAILED", "REJECTED"}:
            raise AssertionError(f"vpc connection entered {last} while waiting for {target_states}")
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"vpc connection {arn} reaching {target_states}: the run budget ended first; not graded")
    raise AssertionError(f"vpc connection did not reach {target_states} within {timeout_s}s (last={last})")



def _wait_until_deletable(kafka, arn, timeout_s=1500.0, interval_s=20.0):
    """MSK refuses DeleteCluster while the cluster is still CREATING or UPDATING; wait it out."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            state = kafka.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["State"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        if state not in ("CREATING", "UPDATING", "REBOOTING_BROKER", "HEALING"):
            return
        time.sleep(interval_s)


def _wait_vpc_connection_deletable(kafka, arn, timeout_s=900.0, interval_s=15.0):
    """DeleteVpcConnection is refused while the connection is still CREATING; wait it out."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            state = kafka.describe_vpc_connection(Arn=arn).get("State")
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        if state not in ("CREATING", "DEACTIVATING", "REJECTING"):
            return
        time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
