"""cluster-policy-enforced-on-cross-account-vpc-connection."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cluster-policy-enforced-on-cross-account-vpc-connection"
GROUP = "server-side"
SERVICES = ["kafka"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateVpcConnection with an unsupported auth type fails with BadRequestException; with a cluster
    policy that explicitly denies it, the same call fails first with AccessDeniedException naming the
    explicit deny, and after DeleteClusterPolicy it reverts to BadRequestException."""

    cluster_arn, subnets, sg_id = _create_provisioned_cluster(ctx, num_brokers=2)
    ec2 = ctx.client("ec2")
    vpc_id = ec2.describe_subnets(SubnetIds=subnets[:1])["Subnets"][0]["VpcId"]
    kafka = ctx.client("kafka")
    principal_arn = _caller_principal_arn(ctx)
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]

    before_arns = {c["VpcConnectionArn"] for c in kafka.list_vpc_connections()["VpcConnections"]}

    def _attempt():
        return kafka.create_vpc_connection(
            TargetClusterArn=cluster_arn,
            Authentication="SASL_IAM",
            VpcId=vpc_id,
            ClientSubnets=subnets,
            SecurityGroups=[sg_id],
        )

    # Baseline: no cluster policy attached yet. This cluster was created without SASL/IAM
    # client authentication enabled, so the call is rejected during request validation.
    baseline_code, baseline_message = _error_of(_attempt)
    assert baseline_code == "BadRequestException", (
        f"expected the baseline (no cluster policy) attempt to fail validation with "
        f"BadRequestException, got {baseline_code!r}"
    )
    assert baseline_message == "SASL/IAM client authentication must be enabled for the cluster.", f"baseline message: {baseline_message!r}"

    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyCreateVpcConnection",
                "Effect": "Deny",
                "Principal": {"AWS": principal_arn},
                "Action": "kafka:CreateVpcConnection",
                "Resource": cluster_arn,
            }
        ],
    }
    kafka.put_cluster_policy(ClusterArn=cluster_arn, Policy=json.dumps(deny_policy))
    policy_attached = {"value": True}
    ctx.on_cleanup(lambda: _delete_policy_if_present(ctx, cluster_arn, policy_attached))

    fetched_policy = json.loads(kafka.get_cluster_policy(ClusterArn=cluster_arn)["Policy"])
    assert fetched_policy == deny_policy, "GetClusterPolicy did not return exactly the policy that was put"

    denied_code, denied_message = _error_of(_attempt)
    assert denied_code == "AccessDeniedException", (
        f"expected the explicit-deny cluster policy to block the call with AccessDeniedException "
        f"ahead of request validation, got {denied_code!r}"
    )
    assert denied_message == (
        f"User: {caller_arn} is not authorized to perform: kafka:CreateVpcConnection on resource: "
        f"{cluster_arn} with an explicit deny in a resource-based policy"
    ), f"explicit-deny message: {denied_message!r}"

    after_deny_arns = {c["VpcConnectionArn"] for c in kafka.list_vpc_connections()["VpcConnections"]}
    assert after_deny_arns == before_arns, "a VPC connection was created despite both attempts being rejected"

    kafka.delete_cluster_policy(ClusterArn=cluster_arn)
    policy_attached["value"] = False
    after_delete_code, after_delete_message = _error_of(lambda: kafka.get_cluster_policy(ClusterArn=cluster_arn))
    assert after_delete_code == "NotFoundException", (
        f"expected GetClusterPolicy to return NotFoundException after DeleteClusterPolicy, "
        f"got {after_delete_code!r}"
    )
    assert after_delete_message == "The requested resource doesn\u2019t exist.", (
        f"GetClusterPolicy message: {after_delete_message!r}"
    )

    # Positive control: with the deny policy gone, the exact same call reverts to the
    # original validation-layer error, proving the ForbiddenException really was the
    # policy's doing and not some other side effect of the earlier calls.
    reverted_code, reverted_message = _error_of(_attempt)
    assert reverted_code == "BadRequestException", (
        f"expected the call to revert to BadRequestException once the deny policy was removed, "
        f"got {reverted_code!r}"
    )
    assert reverted_message == "SASL/IAM client authentication must be enabled for the cluster.", f"reverted message: {reverted_message!r}"


def _error_of(fn):
    """(code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded: {result!r}")


def _caller_principal_arn(ctx) -> str:
    sts = ctx.client("sts")
    ident = sts.get_caller_identity()
    arn = ident["Arn"]
    account = ident["Account"]
    if ":assumed-role/" in arn:
        role_name = arn.split(":assumed-role/")[1].split("/")[0]
        return f"arn:aws:iam::{account}:role/{role_name}"
    return arn


def _delete_policy_if_present(ctx, cluster_arn, policy_attached):
    if not policy_attached["value"]:
        return
    kafka = ctx.client("kafka")
    try:
        kafka.delete_cluster_policy(ClusterArn=cluster_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _default_vpc_subnets_and_sg(ctx, num_azs):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to provision an MSK cluster in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    if len(subnet_ids) < num_azs:
        raise AssertionError(f"shared network has fewer than {num_azs} AZ-distinct network subnets")
    sg = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]
    return subnet_ids[:num_azs], sg["GroupId"]


def _active_kafka_version(ctx):
    kafka = ctx.client("kafka")
    versions = kafka.list_kafka_versions().get("KafkaVersions", [])
    # Kafka 4.x is Express-brokers-only; standard (Provisioned) broker instance
    # types like kafka.t3.small are rejected for those versions, so restrict to
    # ACTIVE versions below the 4.x line.
    active = [
        v["Version"]
        for v in versions
        if v.get("Status") == "ACTIVE" and not v["Version"].startswith("4.")
    ]
    if not active:
        raise AssertionError("ListKafkaVersions returned no ACTIVE Kafka version below 4.x")
    return sorted(active, key=lambda s: [int(p) if p.isdigit() else p for p in s.split(".")])[-1]


def _wait_for_cluster_state(ctx, cluster_arn, target_states, timeout_s=1800, interval_s=20):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        info = kafka.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]
        last = info.get("State")
        if last in target_states:
            return info
        if last == "FAILED":
            raise AssertionError(f"cluster entered FAILED state while waiting for {target_states}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster never reached {target_states}; last observed state={last}")


def _wait_for_cluster_deleted(ctx, cluster_arn, timeout_s=1800, interval_s=20):
    from botocore.exceptions import ClientError

    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            kafka.describe_cluster_v2(ClusterArn=cluster_arn)
        except ClientError as err:
            if err.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_arn} was not deleted within {timeout_s}s")


def _create_provisioned_cluster(ctx, num_brokers=2):
    kafka = ctx.client("kafka")
    subnets, sg_id = _default_vpc_subnets_and_sg(ctx, num_brokers)
    kafka_version = _active_kafka_version(ctx)
    name = ctx.unique_name("sim2real-behav-msk-")
    resp = kafka.create_cluster_v2(
        ClusterName=name,
        Provisioned={
            "BrokerNodeGroupInfo": {
                "InstanceType": "kafka.m5.large",
                "ClientSubnets": subnets,
                "SecurityGroups": [sg_id],
                "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 1}},
            },
            "KafkaVersion": kafka_version,
            "NumberOfBrokerNodes": num_brokers,
        },
        Tags={"sim2real:managed": "true"},
    )
    cluster_arn = resp["ClusterArn"]

    def _cleanup():
        try:
            kafka.delete_cluster(ClusterArn=cluster_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise
            return
        try:
            _wait_for_cluster_deleted(ctx, cluster_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    _wait_for_cluster_state(ctx, cluster_arn, {"ACTIVE"}, timeout_s=1800)
    return cluster_arn, subnets, sg_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
