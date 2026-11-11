"""batch-disassociate-scram-secret-unassociated-secret-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "batch-disassociate-scram-secret-unassociated-secret-rejected"
GROUP = "error-semantics"
SERVICES = ["kafka"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchDisassociateScramSecret on a never-associated secret returns 200 with it in
    UnprocessedScramSecrets (non-empty ErrorCode) and leaves associations untouched;
    disassociating an associated secret returns an empty UnprocessedScramSecrets."""
    kafka = ctx.client("kafka")
    cluster_arn = _create_provisioned_cluster(ctx, sasl_scram=True)
    key_id = _create_kms_key(ctx)
    secret_associated = _create_msk_secret(ctx, key_id)
    secret_never_associated = _create_msk_secret(ctx, key_id)

    # --- Positive control: associate then disassociate a real secret succeeds cleanly. ---
    assoc = kafka.batch_associate_scram_secret(
        ClusterArn=cluster_arn, SecretArnList=[secret_associated]
    )
    assert assoc.get("UnprocessedScramSecrets", []) == [], (
        f"expected the control secret to associate cleanly, got {assoc.get('UnprocessedScramSecrets')}"
    )
    _poll_until(
        lambda: kafka.list_scram_secrets(ClusterArn=cluster_arn)["SecretArnList"],
        lambda arns: secret_associated in arns,
        timeout_s=90,
    )
    disassoc = kafka.batch_disassociate_scram_secret(
        ClusterArn=cluster_arn, SecretArnList=[secret_associated]
    )
    assert disassoc.get("UnprocessedScramSecrets", []) == [], (
        f"expected the control secret to disassociate cleanly, got {disassoc.get('UnprocessedScramSecrets')}"
    )
    _poll_until(
        lambda: kafka.list_scram_secrets(ClusterArn=cluster_arn)["SecretArnList"],
        lambda arns: secret_associated not in arns,
        timeout_s=90,
    )

    # --- Negative: disassociating a secret that was never associated is rejected
    # per-item (UnprocessedScramSecrets), not by a top-level exception. ---
    neg_resp = kafka.batch_disassociate_scram_secret(
        ClusterArn=cluster_arn, SecretArnList=[secret_never_associated]
    )
    unprocessed = neg_resp.get("UnprocessedScramSecrets", [])
    assert len(unprocessed) == 1 and unprocessed[0].get("SecretArn") == secret_never_associated, (
        f"expected the never-associated secret to come back unprocessed, got {unprocessed}"
    )
    assert unprocessed[0].get("ErrorCode"), (
        f"expected a non-empty per-item ErrorCode, got {unprocessed[0]}"
    )

    # Effect absent: the never-associated secret still does not appear as associated.
    arns_after = kafka.list_scram_secrets(ClusterArn=cluster_arn)["SecretArnList"]
    assert secret_never_associated not in arns_after, (
        f"expected {secret_never_associated} to remain unassociated, got {arns_after}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _default_vpc_subnets_sg(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())[:2]
    if len(subnet_ids) < 2:
        raise AssertionError("shared network does not span >=2 availability zones with subnets")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    sg_id = sgs[0]["GroupId"]
    return vpc_id, subnet_ids, sg_id


def _pick_kafka_version(ctx):
    # Standard brokers accept 3.9.x; they reject older versions and the Express-only 4.2.x.
    status = {v["Version"]: v.get("Status") for v in ctx.client("kafka").list_kafka_versions().get("KafkaVersions", [])}
    if status.get("3.9.x") != "ACTIVE":
        raise AssertionError(f"Kafka 3.9.x is not ACTIVE in ListKafkaVersions: {sorted(status)}")
    return "3.9.x"


def _create_provisioned_cluster(ctx, *, sasl_scram=False):
    kafka = ctx.client("kafka")
    _, subnet_ids, sg_id = _default_vpc_subnets_sg(ctx)
    version = _pick_kafka_version(ctx)
    name = ctx.unique_name("sim2real-behav-kafka-")
    kwargs = {
        "ClusterName": name,
        "KafkaVersion": version,
        "NumberOfBrokerNodes": len(subnet_ids),
        "BrokerNodeGroupInfo": {
            "InstanceType": "kafka.t3.small",
            "ClientSubnets": subnet_ids,
            "SecurityGroups": [sg_id],
            "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 1}},
        },
    }
    if sasl_scram:
        kwargs["EncryptionInfo"] = {"EncryptionInTransit": {"ClientBroker": "TLS", "InCluster": True}}
        kwargs["ClientAuthentication"] = {"Sasl": {"Scram": {"Enabled": True}}}
    kwargs["Tags"] = {"sim2real:managed": "true"}
    resp = kafka.create_cluster(**kwargs)
    cluster_arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_when_settled(kafka, cluster_arn))
    _wait_cluster_active(ctx, cluster_arn)
    return cluster_arn


def _wait_cluster_active(ctx, cluster_arn, timeout_s=2700.0, interval_s=30.0):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        info = kafka.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]
        state = info["State"]
        if state == "ACTIVE":
            return info
        if state == "FAILED":
            raise AssertionError(f"cluster {cluster_arn} entered FAILED state while provisioning")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_arn} did not become ACTIVE within {timeout_s}s")


def _create_kms_key(ctx):
    kms = ctx.client("kms")
    key_id = kms.create_key(
        Description="sim2real behavioral test key for MSK SCRAM secrets",
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    return key_id


def _create_msk_secret(ctx, kms_key_id):
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("AmazonMSK_sim2real-")
    resp = sm.create_secret(
        Name=name,
        KmsKeyId=kms_key_id,
        SecretString=json.dumps({"username": "testuser", "password": "TestPassw0rd123!"}),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    secret_arn = resp["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))
    return secret_arn


def _delete_cluster_when_settled(msk, arn, timeout_s=2400.0, interval_s=30.0):
    """DeleteCluster refuses a cluster that is CREATING or UPDATING, so wait for ACTIVE or FAILED first."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            state = msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["State"]
            if state == "DELETING":
                return
            if state in ("ACTIVE", "FAILED"):
                msk.delete_cluster(ClusterArn=arn)
                return
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"cluster {arn} still {state} after {timeout_s:.0f}s; it cannot be deleted")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
