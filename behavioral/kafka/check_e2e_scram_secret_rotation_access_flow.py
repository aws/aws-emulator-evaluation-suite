"""e2e-scram-secret-rotation-access-flow."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "e2e-scram-secret-rotation-access-flow"
GROUP = "e2e"
SERVICES = ["kafka"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Associating a properly provisioned SCRAM secret lists it in ListScramSecrets and disassociating
    removes it; a secret without a customer-managed KMS key is rejected per-secret and never listed.
    """
    kafka = ctx.client("kafka")
    _, subnets, sg = _shared_network(ctx)
    version = _pick_kafka_version(ctx, kafka)
    cluster_arn = _create_scram_cluster(ctx, kafka, subnets, sg, version)
    _wait_for_cluster_active(ctx, kafka, cluster_arn)

    assert kafka.list_scram_secrets(ClusterArn=cluster_arn)["SecretArnList"] == []

    good_secret = _create_scram_secret(ctx, ctx.unique_name("sim2real-behav-kafka-scram-good-"))
    resp = kafka.batch_associate_scram_secret(ClusterArn=cluster_arn, SecretArnList=[good_secret])
    assert resp["UnprocessedScramSecrets"] == []
    assert kafka.list_scram_secrets(ClusterArn=cluster_arn)["SecretArnList"] == [good_secret]

    # Negative: a secret encrypted with the Secrets Manager default (non-customer-managed)
    # key violates the documented MSK SCRAM requirement and must be rejected per-secret,
    # without disturbing the already-associated good secret.
    bad_secret = _create_default_kms_secret(ctx, ctx.unique_name("sim2real-behav-kafka-scram-bad-"))
    resp = kafka.batch_associate_scram_secret(ClusterArn=cluster_arn, SecretArnList=[bad_secret])
    unprocessed = {u["SecretArn"]: u for u in resp["UnprocessedScramSecrets"]}
    assert bad_secret in unprocessed, f"expected the default-key secret to be rejected, response was: {resp}"
    bad_entry = unprocessed[bad_secret]
    assert bad_entry.get("ErrorCode"), f"expected a non-empty ErrorCode for the rejected secret, got: {bad_entry}"
    still_associated = kafka.list_scram_secrets(ClusterArn=cluster_arn)["SecretArnList"]
    assert bad_secret not in still_associated
    assert good_secret in still_associated

    # Revoke: disassociating the good secret removes it from the associated set.
    resp = kafka.batch_disassociate_scram_secret(ClusterArn=cluster_arn, SecretArnList=[good_secret])
    assert resp["UnprocessedScramSecrets"] == []
    assert kafka.list_scram_secrets(ClusterArn=cluster_arn)["SecretArnList"] == []




def _shared_network(ctx, count=2):
    """The run's shared network (ctx.network()): its VPC, count AZ-distinct subnets, its group."""
    net = ctx.network()
    if len(net.subnets) < count:
        raise AssertionError(f"the shared network has {len(net.subnets)} availability-zone subnets, need {count}")
    return net.vpc_id, net.subnet_ids[:count], net.security_group_id


def _pick_kafka_version(ctx, kafka):
    versions = kafka.list_kafka_versions()["KafkaVersions"]
    active = [v["Version"] for v in versions if v.get("Status") == "ACTIVE"]
    return (active or [v["Version"] for v in versions])[0]


def _create_scram_cluster(ctx, kafka, subnets, sg, version):
    name = ctx.unique_name("sim2real-behav-kafka-scram-")
    resp = kafka.create_cluster_v2(
        ClusterName=name,
        Provisioned={
            "BrokerNodeGroupInfo": {
                "InstanceType": "kafka.t3.small",
                "ClientSubnets": subnets,
                "SecurityGroups": [sg],
                "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 10}},
            },
            "KafkaVersion": version,
            "NumberOfBrokerNodes": len(subnets),
            "EncryptionInfo": {"EncryptionInTransit": {"ClientBroker": "TLS"}},
            "ClientAuthentication": {"Sasl": {"Scram": {"Enabled": True}}},
        },
        Tags={"sim2real:managed": "true"},
    )
    arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster(ctx, kafka, arn))
    return arn


def _delete_cluster(ctx, kafka, arn):
    from botocore.exceptions import ClientError

    try:
        kafka.delete_cluster(ClusterArn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NotFoundException":
            return
        raise


def _wait_for_cluster_active(ctx, kafka, arn, timeout_s=1800, interval_s=20):
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        info = kafka.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]
        last_state = info["State"]
        if last_state == "ACTIVE":
            return info
        if last_state == "FAILED":
            raise AssertionError(f"cluster {arn} entered FAILED state")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {arn} did not reach ACTIVE within {timeout_s}s (last={last_state})")


def _create_scram_secret(ctx, suffix, username="testuser", password="Testpassw0rd!123"):
    kms = ctx.client("kms")
    key_id = kms.create_key(
        Description="sim2real-behav-kafka-scram-cmk",
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    sm = ctx.client("secretsmanager")
    secret_name = f"AmazonMSK_{suffix}"
    secret = sm.create_secret(
        Name=secret_name,
        KmsKeyId=key_id,
        SecretString=json.dumps({"username": username, "password": password}),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    secret_arn = secret["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))
    return secret_arn


def _create_default_kms_secret(ctx, suffix, username="baduser", password="Testpassw0rd!123"):
    sm = ctx.client("secretsmanager")
    secret_name = f"AmazonMSK_{suffix}"
    secret = sm.create_secret(
        Name=secret_name,
        SecretString=json.dumps({"username": username, "password": password}),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    secret_arn = secret["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))
    return secret_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
