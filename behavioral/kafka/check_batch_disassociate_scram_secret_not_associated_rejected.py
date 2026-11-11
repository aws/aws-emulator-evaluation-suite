"""batch-disassociate-scram-secret-not-associated-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "batch-disassociate-scram-secret-not-associated-rejected"
GROUP = "error-semantics"
SERVICES = ["kafka"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Disassociating a never-associated SCRAM secret returns 200 with a per-item UnprocessedScramSecrets error.

    The associated-secret list stays unchanged, and disassociating the associated secret then succeeds.
    """
    kafka = ctx.client("kafka")
    _vpc_id, subnet_ids, sg_id = _default_vpc_subnets(ctx, count=2)
    cluster_arn = _create_msk_cluster(ctx, ctx.unique_name("sim2real-kafka-scram-"), subnet_ids, sg_id)

    secret_a = _create_scram_secret(ctx, ctx.unique_name("AmazonMSK_sim2real_a_"))
    secret_b = _create_scram_secret(ctx, ctx.unique_name("AmazonMSK_sim2real_b_"))

    assoc = kafka.batch_associate_scram_secret(ClusterArn=cluster_arn, SecretArnList=[secret_a])
    assert assoc.get("UnprocessedScramSecrets", []) == []

    disassoc_b = kafka.batch_disassociate_scram_secret(ClusterArn=cluster_arn, SecretArnList=[secret_b])
    unprocessed = disassoc_b.get("UnprocessedScramSecrets", [])
    assert len(unprocessed) == 1 and unprocessed[0].get("SecretArn") == secret_b, (
        f"expected {secret_b!r} to come back as the sole unprocessed item, got {unprocessed!r}"
    )
    assert unprocessed[0].get("ErrorCode"), f"expected a non-empty per-item ErrorCode, got {unprocessed[0]!r}"

    associated = kafka.list_scram_secrets(ClusterArn=cluster_arn)["SecretArnList"]
    assert associated == [secret_a], (
        f"expected the associated-secret list to be unchanged ([{secret_a}]), got {associated}"
    )

    # Positive control: disassociating the secret that really is associated works.
    disassoc = kafka.batch_disassociate_scram_secret(ClusterArn=cluster_arn, SecretArnList=[secret_a])
    assert disassoc.get("UnprocessedScramSecrets", []) == []
    associated_after = kafka.list_scram_secrets(ClusterArn=cluster_arn)["SecretArnList"]
    assert secret_a not in associated_after


# ===== helpers =====
def _default_vpc_subnets(ctx, count: int):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("account has no shared network to provision an MSK test cluster in")
    vpc_id = vpcs[0]["VpcId"]
    # ctx.network() holds exactly one subnet per availability zone, so any slice of these
    # subnets lands in distinct AZs, as CreateCluster requires.
    subnets = ec2.describe_subnets(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ]
    )["Subnets"]
    if len(subnets) < count:
        raise AssertionError("shared network does not have enough subnets to provision an MSK test cluster")
    sg = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]
    return vpc_id, [s["SubnetId"] for s in subnets[:count]], sg


def _pick_kafka_version(ctx):
    # Standard brokers accept 3.9.x; they reject older versions and the Express-only 4.2.x.
    status = {v["Version"]: v.get("Status") for v in ctx.client("kafka").list_kafka_versions().get("KafkaVersions", [])}
    if status.get("3.9.x") != "ACTIVE":
        raise AssertionError(f"Kafka 3.9.x is not ACTIVE in ListKafkaVersions: {sorted(status)}")
    return "3.9.x"


def _create_msk_cluster(ctx, name, subnet_ids, sg_id, *, num_brokers=None):
    kafka = ctx.client("kafka")
    num_brokers = num_brokers or len(subnet_ids)
    resp = kafka.create_cluster(
        ClusterName=name,
        KafkaVersion=_pick_kafka_version(ctx),
        NumberOfBrokerNodes=num_brokers,
        BrokerNodeGroupInfo={
            "InstanceType": "kafka.t3.small",
            "ClientSubnets": subnet_ids,
            "SecurityGroups": [sg_id],
            "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 1}},
        },
        ClientAuthentication={"Sasl": {"Scram": {"Enabled": True}}},
        EncryptionInfo={"EncryptionInTransit": {"ClientBroker": "TLS", "InCluster": True}},
    )
    arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster(ctx, arn))
    _wait_cluster_state(ctx, arn, {"ACTIVE"}, timeout_s=1800, interval_s=20)
    return arn


def _delete_cluster(ctx, arn):
    from botocore.exceptions import ClientError

    try:
        ctx.client("kafka").delete_cluster(ClusterArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _wait_cluster_state(ctx, arn, ok_states, *, timeout_s, interval_s):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        info = kafka.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]
        last = info["State"]
        if last in ok_states:
            return info
        if last == "FAILED":
            raise AssertionError(f"cluster entered FAILED state while waiting for {ok_states}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster did not reach {ok_states} within {timeout_s}s (last state={last})")


def _create_scram_secret(ctx, name: str) -> str:
    kms = ctx.client("kms")
    secretsmanager = ctx.client("secretsmanager")

    key_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "RootAccess",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{ctx.client('sts').get_caller_identity()['Account']}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "AllowMskUse",
                "Effect": "Allow",
                "Principal": {"Service": "kafka.amazonaws.com"},
                "Action": ["kms:Decrypt", "kms:DescribeKey", "kms:CreateGrant", "kms:GenerateDataKey"],
                "Resource": "*",
            },
        ],
    }
    key_id = kms.create_key(Description="sim2real kafka scram secret key", Policy=json.dumps(key_policy))[
        "KeyMetadata"
    ]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    secret = secretsmanager.create_secret(
        Name=name,
        KmsKeyId=key_id,
        SecretString=json.dumps({"username": "sim2real-user", "password": "Sim2Real-Passw0rd!"}),
    )
    secret_arn = secret["ARN"]
    ctx.on_cleanup(lambda: secretsmanager.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))
    return secret_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
