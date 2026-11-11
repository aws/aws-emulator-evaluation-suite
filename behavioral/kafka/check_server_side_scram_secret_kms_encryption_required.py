"""server-side-scram-secret-kms-encryption-required."""
from __future__ import annotations

import json
import secrets
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "server-side-scram-secret-kms-encryption-required"
GROUP = "server-side"
SERVICES = ["kafka"]


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """In one BatchAssociateScramSecret call, a secret encrypted with the default Secrets Manager key comes back
    in UnprocessedScramSecrets with InvalidSecretArn and a message naming the default key and is never listed,
    while a secret under a customer-managed KMS key is associated."""
    kafka = ctx.client("kafka")
    kms = ctx.client("kms")
    sm = ctx.client("secretsmanager")

    cluster_arn = _create_scram_cluster(ctx, "sim2real-kmsreq")

    key_id = kms.create_key(
        Description="sim2real kafka scram secret key",
        Tags=[{"TagKey": "sim2real-check", "TagValue": CHECK}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: _safe(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)))

    good_name = f"AmazonMSK_{ctx.unique_name('kmsgood')}"
    good_arn = sm.create_secret(
        Name=good_name,
        KmsKeyId=key_id,
        SecretString=json.dumps({"username": "sim2real-good", "password": secrets.token_urlsafe(18)}),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["ARN"]
    ctx.on_cleanup(lambda: _safe(lambda: sm.delete_secret(SecretId=good_arn, ForceDeleteWithoutRecovery=True)))

    bad_name = f"AmazonMSK_{ctx.unique_name('kmsbad')}"
    bad_arn = sm.create_secret(
        Name=bad_name,
        # No KmsKeyId -> Secrets Manager falls back to the account default
        # aws/secretsmanager key, which MSK documents as unsupported.
        SecretString=json.dumps({"username": "sim2real-bad", "password": secrets.token_urlsafe(18)}),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["ARN"]
    ctx.on_cleanup(lambda: _safe(lambda: sm.delete_secret(SecretId=bad_arn, ForceDeleteWithoutRecovery=True)))

    resp = kafka.batch_associate_scram_secret(ClusterArn=cluster_arn, SecretArnList=[good_arn, bad_arn])
    unprocessed = {u["SecretArn"]: u for u in resp.get("UnprocessedScramSecrets", [])}

    assert bad_arn in unprocessed, f"expected the default-key secret to be rejected, response was: {resp}"
    bad_entry = unprocessed[bad_arn]
    error_code = bad_entry.get("ErrorCode")
    assert error_code == "InvalidSecretArn", (
        f"expected the default-key secret rejection to report the specific "
        f"ErrorCode InvalidSecretArn, got: {bad_entry}"
    )
    error_message = bad_entry.get("ErrorMessage") or ""
    assert "default" in error_message.lower() and "key" in error_message.lower(), (
        "expected InvalidSecretArn's message to name the default-key restriction "
        f"(not e.g. a malformed-ARN complaint), got: {bad_entry}"
    )
    assert good_arn not in unprocessed, f"KMS-encrypted secret was unexpectedly rejected too: {resp}"

    associated = kafka.list_scram_secrets(ClusterArn=cluster_arn).get("SecretArnList", [])
    assert good_arn in associated, f"KMS-encrypted secret did not actually become associated: {associated}"
    assert bad_arn not in associated, f"default-key secret was associated despite being rejected: {associated}"


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


#: The suite's cleanup budget; the cluster and security group teardowns share one deadline inside it.
_CLEANUP_BUDGET_S = 1800.0


def _teardown_deadline(ctx) -> float:
    """The run's one cleanup deadline, started by the first teardown that asks for it."""
    if getattr(ctx, "_kafka_teardown_deadline", None) is None:
        ctx._kafka_teardown_deadline = time.monotonic() + _CLEANUP_BUDGET_S
    return ctx._kafka_teardown_deadline


def _create_open_security_group(ctx, vpc_id: str, name: str) -> str:
    ec2 = ctx.client("ec2")
    sg_id = ec2.create_security_group(
        GroupName=name,
        Description="sim2real kafka behavioral check",
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "sim2real-check", "Value": CHECK}]}
        ],
    )["GroupId"]

    def _cleanup():
        # Registered before the cluster, so it runs after the cluster is gone; broker ENIs can still
        # hold the group (DependencyViolation) briefly, retried to the shared cleanup deadline.
        deadline = _teardown_deadline(ctx)
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


def _wait_cluster_active(ctx, cluster_arn: str, timeout_s: float = 2700.0, interval_s: float = 10.0):
    # A 3-broker express.m7g.large cluster can take ~39 min to reach ACTIVE.
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


def _create_scram_cluster(ctx, name_prefix: str) -> str:
    """Create a private SASL/SCRAM-enabled cluster; no native Kafka connection is needed."""
    kafka = ctx.client("kafka")
    version = _pick_kafka_version(ctx)
    vpc_id, subnets = _pick_subnets(ctx, 3)
    sg_id = _create_open_security_group(ctx, vpc_id, ctx.unique_name(f"{name_prefix}-sg-"))

    cluster_name = ctx.unique_name(f"{name_prefix}-")
    cluster_arn = kafka.create_cluster_v2(
        ClusterName=cluster_name,
        Provisioned={
            "KafkaVersion": version,
            "NumberOfBrokerNodes": 3,
            "ClientAuthentication": {"Sasl": {"Scram": {"Enabled": True}}},
            "EncryptionInfo": {"EncryptionInTransit": {"ClientBroker": "TLS", "InCluster": True}},
            "BrokerNodeGroupInfo": {
                "InstanceType": "express.m7g.large",
                "ClientSubnets": subnets,
                "SecurityGroups": [sg_id],
            },
        },
        Tags={"sim2real-check": CHECK},
    )["ClusterArn"]

    def _cleanup():
        # Waits until the cluster is gone, so the security group delete after it can succeed.
        try:
            kafka.delete_cluster(ClusterArn=cluster_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise
            return
        deadline = _teardown_deadline(ctx)
        while time.monotonic() < deadline:
            try:
                kafka.describe_cluster_v2(ClusterArn=cluster_arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "NotFoundException":
                    return
                raise
            time.sleep(2)
        raise AssertionError(f"cluster {cluster_arn} still present at the cleanup deadline after DeleteCluster")

    ctx.on_cleanup(_cleanup)
    _wait_cluster_active(ctx, cluster_arn)
    return cluster_arn


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NotFoundException", "ResourceNotFoundException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
