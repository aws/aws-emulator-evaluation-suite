"""scram-secret-batch-operations-partial-failure-isolation."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "scram-secret-batch-operations-partial-failure-isolation"
GROUP = "error-semantics"
SERVICES = ["kafka"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchDisassociateScramSecret with one associated and one nonexistent secret ARN disassociates
    the valid one and reports an error only for the invalid entry (not all-or-nothing); an
    all-valid batch fully succeeds."""
    cluster_arn, _subnets, _sg = _create_provisioned_cluster_scram(ctx, num_brokers=2)
    kafka = ctx.client("kafka")
    secret_arn = _create_scram_secret(ctx)
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bogus_arn = f"arn:aws:secretsmanager:{ctx.region}:{account_id}:secret:AmazonMSK_sim2real-nonexistent-abcdef"

    assoc = kafka.batch_associate_scram_secret(ClusterArn=cluster_arn, SecretArnList=[secret_arn])
    assert assoc["UnprocessedScramSecrets"] == []
    assert secret_arn in kafka.list_scram_secrets(ClusterArn=cluster_arn)["SecretArnList"]

    disassoc = kafka.batch_disassociate_scram_secret(
        ClusterArn=cluster_arn, SecretArnList=[secret_arn, bogus_arn]
    )
    unprocessed = disassoc["UnprocessedScramSecrets"]
    assert len(unprocessed) == 1, f"expected exactly one unprocessed entry, got {unprocessed}"
    assert unprocessed[0]["SecretArn"] == bogus_arn
    assert unprocessed[0].get("ErrorCode"), f"expected a non-empty per-item ErrorCode, got {unprocessed[0]!r}"

    remaining = kafka.list_scram_secrets(ClusterArn=cluster_arn)["SecretArnList"]
    assert secret_arn not in remaining, "the valid secret was not disassociated despite the batch reporting a partial failure"

    # Positive control: an all-valid batch (re-associate then fully disassociate) succeeds
    # cleanly, proving the earlier partial failure wasn't a systemic rejection.
    kafka.batch_associate_scram_secret(ClusterArn=cluster_arn, SecretArnList=[secret_arn])
    clean_disassoc = kafka.batch_disassociate_scram_secret(ClusterArn=cluster_arn, SecretArnList=[secret_arn])
    assert clean_disassoc["UnprocessedScramSecrets"] == []
    assert secret_arn not in kafka.list_scram_secrets(ClusterArn=cluster_arn)["SecretArnList"]


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


def _create_provisioned_cluster_scram(ctx, num_brokers=2):
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
            "EncryptionInfo": {"EncryptionInTransit": {"ClientBroker": "TLS", "InCluster": True}},
            "ClientAuthentication": {"Sasl": {"Scram": {"Enabled": True}}},
        },
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


def _create_scram_secret(ctx):
    kms = ctx.client("kms")
    secretsmanager = ctx.client("secretsmanager")

    key = kms.create_key(Description="sim2real behavioral check - MSK SCRAM secret encryption")["KeyMetadata"]
    key_id = key["KeyId"]

    def _cleanup_key():
        try:
            kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup_key)

    secret_name = ctx.unique_name("AmazonMSK_sim2real_behav_")
    secret = secretsmanager.create_secret(
        Name=secret_name,
        KmsKeyId=key_id,
        SecretString=json.dumps({"username": "sim2real-behav-user", "password": "Sim2Real-Behav-Passw0rd!"}),
    )
    secret_arn = secret["ARN"]

    def _cleanup_secret():
        try:
            secretsmanager.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_secret)
    return secret_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
