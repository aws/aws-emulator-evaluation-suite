"""server-side-cluster-policy-cross-account-enforcement."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "server-side-cluster-policy-cross-account-enforcement"
GROUP = "server-side"
SERVICES = ["kafka"]


@tags("axis:rejection", "cap:c4", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An explicit Deny in a PutClusterPolicy resource policy overrides the caller's IAM Allow.

    GetBootstrapBrokers succeeds without a policy, is denied (AccessDeniedException) once a policy
    denying the caller is attached, and succeeds again after the policy is deleted.
    """
    kafka = ctx.client("kafka")
    ctx.client("sts")

    cluster_arn = _create_minimal_cluster(ctx, "sim2real-clpolicy")

    # No policy attached yet: GetClusterPolicy is NotFoundException, and the
    # control-plane call the policy will later gate succeeds normally.
    no_policy_code, no_policy_message = _error_code(lambda: kafka.get_cluster_policy(ClusterArn=cluster_arn))
    assert no_policy_code == "NotFoundException", f"expected NotFoundException with no policy attached, got {no_policy_code}"
    assert no_policy_message == "The requested resource doesn\u2019t exist.", (
        f"GetClusterPolicy message: {no_policy_message!r}"
    )

    baseline = kafka.get_bootstrap_brokers(ClusterArn=cluster_arn)
    assert any(k.startswith("BootstrapBrokerString") for k in baseline), f"unexpected GetBootstrapBrokers response: {baseline}"

    principal_arn = _caller_principal_arn(ctx)
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyGetBootstrapBrokersForCaller",
                "Effect": "Deny",
                "Principal": {"AWS": principal_arn},
                "Action": "kafka:GetBootstrapBrokers",
                "Resource": cluster_arn,
            }
        ],
    }
    kafka.put_cluster_policy(ClusterArn=cluster_arn, Policy=json.dumps(deny_policy))
    ctx.on_cleanup(lambda: _safe(lambda: kafka.delete_cluster_policy(ClusterArn=cluster_arn)))

    fetched = kafka.get_cluster_policy(ClusterArn=cluster_arn)
    fetched_statement = json.loads(fetched["Policy"])["Statement"][0]
    assert fetched_statement["Sid"] == "DenyGetBootstrapBrokersForCaller", f"unexpected policy round-trip: {fetched}"

    # The Deny surfaces as AccessDeniedException, not ForbiddenException (the code GetClusterPolicy
    # itself returns when denied). Polled because the policy takes effect eventually.
    denied_code, denied_message = _poll_for_error_code(
        lambda: kafka.get_bootstrap_brokers(ClusterArn=cluster_arn), "AccessDeniedException", timeout_s=60.0
    )
    assert denied_code == "AccessDeniedException", f"expected AccessDeniedException once the deny policy is attached, got {denied_code}"
    assert denied_message == (
        f"User: {caller_arn} is not authorized to perform: kafka:GetBootstrapBrokers on resource: "
        f"{cluster_arn} with an explicit deny in a resource-based policy"
    ), f"explicit-deny message: {denied_message!r}"

    # Remove the policy: access must be restored -- proving the policy, not the
    # cluster's general state, was responsible for the denial.
    kafka.delete_cluster_policy(ClusterArn=cluster_arn)
    restored = _poll_for_success(lambda: kafka.get_bootstrap_brokers(ClusterArn=cluster_arn), timeout_s=60.0)
    assert any(k.startswith("BootstrapBrokerString") for k in restored), f"unexpected response after policy removal: {restored}"


def _error_code(fn):
    """(code, message) of the ClientError fn raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded: {result!r}")


def _poll_for_error_code(fn, expected_code: str, timeout_s: float, interval_s: float = 5.0):
    """(code, message) of the first ClientError with expected_code; a success or another code polls on."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            fn()
            last = "success"
        except ClientError as e:
            last = e.response["Error"]["Code"]
            if last == expected_code:
                return last, e.response["Error"].get("Message")
        time.sleep(interval_s)
    raise AssertionError(f"expected error code {expected_code!r} within {timeout_s}s, last observed: {last!r}")


def _poll_for_success(fn, timeout_s: float, interval_s: float = 5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            last_exc = e
            time.sleep(interval_s)
    raise AssertionError(f"call never succeeded within {timeout_s}s: {last_exc}")


def _caller_principal_arn(ctx) -> str:
    sts = ctx.client("sts")
    ident = sts.get_caller_identity()
    arn = ident["Arn"]
    account = ident["Account"]
    if ":assumed-role/" in arn:
        role_name = arn.split(":assumed-role/")[1].split("/")[0]
        return f"arn:aws:iam::{account}:role/{role_name}"
    return arn


def _pick_kafka_version(ctx) -> str:
    """Express brokers support only Apache Kafka 3.8.x, 3.9.x.kraft and 4.2.x.kraft."""
    status = {v["Version"]: v.get("Status") for v in ctx.client("kafka").list_kafka_versions().get("KafkaVersions", [])}
    if status.get("3.8.x") != "ACTIVE":
        raise AssertionError(f"Kafka 3.8.x is not ACTIVE in ListKafkaVersions: {sorted(status)}")
    return "3.8.x"


def _pick_subnets(ctx, count: int):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to host a test MSK cluster")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    chosen = list(by_az.values())[:count]
    if len(chosen) < count:
        raise AssertionError(f"shared network has fewer than {count} distinct availability zones available")
    return vpc_id, chosen


def _create_open_security_group(ctx, vpc_id: str, name: str) -> str:
    ec2 = ctx.client("ec2")
    sg_id = ec2.create_security_group(
        GroupName=name,
        Description="sim2real kafka behavioral check",
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "sim2real-clpolicy", "Value": "1"}]}
        ],
    )["GroupId"]

    def _cleanup():
        # Registered before the cluster, so it runs after DeleteCluster; the deleting brokers'
        # ENIs hold the group (DependencyViolation) until MSK releases them.
        deadline = time.monotonic() + 1500.0
        while True:
            try:
                ec2.delete_security_group(GroupId=sg_id)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "InvalidGroup.NotFound":
                    return
                if code != "DependencyViolation" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    ctx.on_cleanup(_cleanup)
    return sg_id


def _wait_cluster_active(ctx, cluster_arn: str, timeout_s: float = 2700.0, interval_s: float = 30.0):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        info = kafka.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]
        state = info.get("State")
        if state == "ACTIVE":
            return info
        if state == "FAILED":
            raise AssertionError(f"cluster {cluster_arn} entered FAILED state: {info}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_arn} did not reach ACTIVE within {timeout_s}s")


def _create_minimal_cluster(ctx, name_prefix: str) -> str:
    kafka = ctx.client("kafka")
    version = _pick_kafka_version(ctx)
    vpc_id, subnets = _pick_subnets(ctx, 3)
    sg_id = _create_open_security_group(ctx, vpc_id, ctx.unique_name(f"{name_prefix}-sg-"))

    cluster_name = ctx.unique_name(f"{name_prefix}-")
    cluster_arn = kafka.create_cluster_v2(
        ClusterName=cluster_name,
        Tags={"sim2real-clpolicy": "1"},
        Provisioned={
            "KafkaVersion": version,
            "NumberOfBrokerNodes": 3,
            "ClientAuthentication": {"Unauthenticated": {"Enabled": True}},
            "EncryptionInfo": {"EncryptionInTransit": {"ClientBroker": "TLS_PLAINTEXT", "InCluster": True}},
            "BrokerNodeGroupInfo": {
                "InstanceType": "express.m7g.large",
                "ClientSubnets": subnets,
                "SecurityGroups": [sg_id],
            },
        },
    )["ClusterArn"]

    def _cleanup():
        try:
            kafka.delete_cluster(ClusterArn=cluster_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    _wait_cluster_active(ctx, cluster_arn)
    return cluster_arn


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
