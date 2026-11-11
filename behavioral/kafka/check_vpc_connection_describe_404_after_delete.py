"""vpc-connection-describe-404-after-delete."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "vpc-connection-describe-404-after-delete"
GROUP = "state-machine"
SERVICES = ["kafka"]

_CLUSTER_WAIT_TIMEOUT_S = 2700


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A VPC connection transitions AVAILABLE -> (DeleteVpcConnection) -> DELETING -> gone; after
    that, DescribeVpcConnection and a second delete fail with NotFoundException and its exact message."""
    cluster_arn = _create_provisioned_cluster(
        ctx,
        client_authentication={"Sasl": {"Iam": {"Enabled": True}}},
        connectivity_info={"VpcConnectivity": {"ClientAuthentication": {"Sasl": {"Iam": {"Enabled": False}}}}},
    )
    kafka = ctx.client("kafka")
    _enable_multi_vpc_connectivity(ctx, kafka, cluster_arn)
    vpc_id, subnet_ids, sg_id = _default_vpc_subnets_and_sg(ctx)

    created = kafka.create_vpc_connection(
        TargetClusterArn=cluster_arn,
        Authentication="SASL_IAM",
        VpcId=vpc_id,
        ClientSubnets=subnet_ids,
        SecurityGroups=[sg_id],
        Tags={"sim2real:managed": "true"},
    )
    vpc_conn_arn = created["VpcConnectionArn"]

    def _best_effort_delete_vpc_connection():
        try:
            kafka.delete_vpc_connection(Arn=vpc_conn_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_best_effort_delete_vpc_connection)

    available = _poll_until(
        ctx,
        lambda: kafka.describe_vpc_connection(Arn=vpc_conn_arn),
        lambda r: r["State"] == "AVAILABLE",
        timeout_s=1800,
    )
    assert available["State"] == "AVAILABLE", f"expected State=AVAILABLE, got {available['State']!r}"
    assert available["VpcConnectionArn"] == vpc_conn_arn, (
        f"expected VpcConnectionArn={vpc_conn_arn!r}, got {available['VpcConnectionArn']!r}"
    )
    assert available["TargetClusterArn"] == cluster_arn, (
        f"expected TargetClusterArn={cluster_arn!r}, got {available['TargetClusterArn']!r}"
    )

    kafka.delete_vpc_connection(Arn=vpc_conn_arn)

    code = _poll_until(
        ctx,
        lambda: _error_code(lambda: kafka.describe_vpc_connection(Arn=vpc_conn_arn)),
        lambda c: c != "present",
        timeout_s=900,
    )
    assert code == _NOT_FOUND, f"expected DescribeVpcConnection to 404 with {_NOT_FOUND!r}, got {code!r}"

    # A mutation on the dead id must also fail, not just a read -- the id is gone, not stale.
    redelete_code = _error_code(lambda: kafka.delete_vpc_connection(Arn=vpc_conn_arn))
    assert redelete_code == _NOT_FOUND, (
        f"expected a second DeleteVpcConnection on the deleted arn to 404 with "
        f"{_NOT_FOUND!r}, got {redelete_code!r}"
    )


# ===== helpers =====
_NOT_FOUND = ("NotFoundException", "The requested resource doesn\u2019t exist.")


def _error_code(fn):
    """Call fn(); return the (code, message) of the ClientError it raises, or "present" when it succeeds."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    return "present"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, *, timeout_s):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"waiting on {result!r}: the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s:.0f}s (last observed: {result!r})")


def _default_vpc_subnets_and_sg(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to provision an MSK broker cluster")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("shared network lacks subnets in at least 2 AZs required to place MSK broker nodes")
    subnet_ids = list(by_az.values())[:2]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    sg_id = sgs[0]["GroupId"]
    return vpc_id, subnet_ids, sg_id


def _active_kafka_versions_desc(ctx):
    kafka = ctx.client("kafka")
    versions = kafka.list_kafka_versions().get("KafkaVersions", [])
    active = sorted({v["Version"] for v in versions if v.get("Status") == "ACTIVE"}, reverse=True)
    if not active:
        raise AssertionError("no ACTIVE Kafka version reported by ListKafkaVersions")
    return active


def _wait_for_cluster_state(ctx, arn, target_state, timeout_s=_CLUSTER_WAIT_TIMEOUT_S):
    kafka = ctx.client("kafka")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        info = kafka.describe_cluster(ClusterArn=arn)["ClusterInfo"]
        last = info["State"]
        if last == target_state:
            return info
        if last == "FAILED":
            raise AssertionError(f"cluster {arn} entered FAILED state while waiting for {target_state}")
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"cluster {arn} reaching {target_state}: the run budget ended first; not graded")
    raise AssertionError(f"cluster {arn} did not reach {target_state} within {timeout_s:.0f}s (last observed: {last})")


def _enable_multi_vpc_connectivity(ctx, kafka, cluster_arn, timeout_s=4800):
    """Turn on multi-VPC private connectivity (SASL/IAM) for an ACTIVE cluster.

    CreateClusterV2 refuses a vpcConnectivity auth scheme with 'enabled: true' at create time
    ("all vpcConnectivity auth schemes must be disabled ... You can enable auth schemes after the
    cluster is created" -- read directly off a real-AWS BadRequestException); it must be turned on
    afterward with UpdateConnectivity, which starts a rolling broker reboot AWS documents as taking
    "up to 30 minutes or more". CreateVpcConnection would otherwise fail for an unrelated reason
    (the cluster mid-update), so this polls the cluster OPERATION to completion rather than
    assuming the call is synchronous.
    """
    current_version = kafka.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]["CurrentVersion"]
    resp = kafka.update_connectivity(
        ClusterArn=cluster_arn,
        CurrentVersion=current_version,
        ConnectivityInfo={"VpcConnectivity": {"ClientAuthentication": {"Sasl": {"Iam": {"Enabled": True}}}}},
    )
    op_arn = resp["ClusterOperationArn"]
    info = _poll_until(
        ctx,
        lambda: kafka.describe_cluster_operation_v2(ClusterOperationArn=op_arn)["ClusterOperationInfo"],
        lambda i: i.get("OperationState", "").endswith(("COMPLETE", "COMPLETED", "FAILED")),
        timeout_s=timeout_s,
    )
    state = info.get("OperationState")
    assert state == "UPDATE_COMPLETE", (
        f"expected UpdateConnectivity to reach UPDATE_COMPLETE, got {state!r} ({info.get('ErrorInfo')})"
    )


def _delete_cluster_and_wait(ctx, arn, timeout_s=1500):
    """Delete the cluster and poll it to NotFoundException within the suite's cleanup budget."""
    kafka = ctx.client("kafka")
    try:
        kafka.delete_cluster(ClusterArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            kafka.describe_cluster(ClusterArn=arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"cluster {arn} was still describable {timeout_s}s after DeleteCluster")


def _create_provisioned_cluster(ctx, *, client_authentication=None, connectivity_info=None, kafka_version=None):
    """Create a 2-broker kafka.m5.large PROVISIONED cluster and wait for ACTIVE.

    Not every ACTIVE Kafka version supports the standard (non-Express) broker instance types --
    AWS added a version to the ACTIVE set (for example 4.2.x.kraft) that CreateClusterV2
    rejects for kafka.m5.large with "Standard instance types are not supported for Kafka version
    ...". ListKafkaVersions carries no field that predicts this, so the real compatibility is
    measured by retrying from newest to oldest ACTIVE version and reading CreateClusterV2's own
    BadRequestException, rather than pinning a version list that would go stale.
    """
    kafka = ctx.client("kafka")
    _vpc_id, subnet_ids, sg_id = _default_vpc_subnets_and_sg(ctx)
    candidates = [kafka_version] if kafka_version else _active_kafka_versions_desc(ctx)
    broker_node_group_info = {
        "InstanceType": "kafka.m5.large",
        "ClientSubnets": subnet_ids,
        "SecurityGroups": [sg_id],
    }
    if connectivity_info is not None:
        broker_node_group_info["ConnectivityInfo"] = connectivity_info

    resp = None
    last_error = None
    for version in candidates:
        provisioned = {
            "BrokerNodeGroupInfo": broker_node_group_info,
            "KafkaVersion": version,
            "NumberOfBrokerNodes": len(subnet_ids),
        }
        if client_authentication is not None:
            provisioned["ClientAuthentication"] = client_authentication
        try:
            resp = kafka.create_cluster_v2(
                ClusterName=ctx.unique_name("sim2real-msk-"),
                Provisioned=provisioned,
                Tags={"sim2real:managed": "true"},
            )
            break
        except ClientError as e:
            if "not supported for Kafka version" not in e.response.get("Error", {}).get("Message", ""):
                raise
            last_error = e
    if resp is None:
        raise AssertionError(
            f"no ACTIVE Kafka version among {candidates} supports kafka.m5.large broker nodes: {last_error}"
        )
    arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(ctx, arn))
    _wait_for_cluster_state(ctx, arn, "ACTIVE")
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
