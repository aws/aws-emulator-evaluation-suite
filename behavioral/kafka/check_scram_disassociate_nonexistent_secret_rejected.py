"""scram-disassociate-nonexistent-secret-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "scram-disassociate-nonexistent-secret-rejected"
GROUP = "error-semantics"
SERVICES = ["kafka"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BatchDisassociateScramSecret returns a never-associated secret ARN in UnprocessedScramSecrets with
    an error code, while the associated secret in the same call is disassociated cleanly."""
    cluster_arn = _create_active_msk_cluster(ctx, sasl_scram=True)
    kafka = ctx.client("kafka")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    associated_secret_arn = _create_scram_secret(ctx)
    bogus_secret_arn = (
        f"arn:aws:secretsmanager:{ctx.region}:{account_id}:secret:"
        f"AmazonMSK_{ctx.unique_name('never-associated-')}-abcdef"
    )

    # Positive control: associating a real secret works cleanly and it shows up as associated.
    assoc = kafka.batch_associate_scram_secret(
        ClusterArn=cluster_arn, SecretArnList=[associated_secret_arn]
    )
    assert assoc.get("UnprocessedScramSecrets", []) == [], (
        f"expected the association to succeed cleanly, got {assoc.get('UnprocessedScramSecrets')}"
    )
    _wait_until(
        lambda: associated_secret_arn
        in kafka.list_scram_secrets(ClusterArn=cluster_arn).get("SecretArnList", []),
        reason="secret never showed up as associated",
    )

    before = kafka.list_scram_secrets(ClusterArn=cluster_arn).get("SecretArnList", [])
    assert bogus_secret_arn not in before

    # Twin control in the same call: the bogus ARN must be rejected per-item while the
    # genuinely associated ARN in the same request disassociates cleanly.
    resp = kafka.batch_disassociate_scram_secret(
        ClusterArn=cluster_arn, SecretArnList=[bogus_secret_arn, associated_secret_arn]
    )
    unprocessed = resp.get("UnprocessedScramSecrets", [])
    matches = [u for u in unprocessed if u.get("SecretArn") == bogus_secret_arn]
    assert len(matches) == 1, f"expected a per-secret error entry for the bogus ARN, got {unprocessed}"
    assert matches[0].get("ErrorCode"), "expected a non-empty ErrorCode for the unassociated secret"
    assert not any(u.get("SecretArn") == associated_secret_arn for u in unprocessed), (
        f"expected the genuinely associated secret to disassociate cleanly in the same call, "
        f"got {unprocessed}"
    )

    # Effect absent: the bogus secret was never associated, and it still isn't.
    after = kafka.list_scram_secrets(ClusterArn=cluster_arn).get("SecretArnList", [])
    assert bogus_secret_arn not in after
    # Effect present: the genuinely associated secret really was disassociated by that call.
    _wait_until(
        lambda: associated_secret_arn
        not in kafka.list_scram_secrets(ClusterArn=cluster_arn).get("SecretArnList", []),
        reason="associated secret never showed up as disassociated",
    )


def _default_vpc_subnets(ctx, count=2):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    if len(subnet_ids) < count:
        raise AssertionError(
            "VPC does not have enough distinct-AZ subnets to provision an MSK cluster"
        )
    return vpc_id, subnet_ids[:count]


def _wait_until(predicate, *, timeout_s=120.0, interval_s=5.0, reason="condition not met"):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(interval_s)
    raise AssertionError(f"{reason} within {timeout_s}s")


def _create_scram_secret(ctx) -> str:
    kms = ctx.client("kms")
    secretsmanager = ctx.client("secretsmanager")

    key_id = kms.create_key(
        Description="sim2real kafka scram secret key",
        Tags=[{"TagKey": "sim2real", "TagValue": "true"}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    name = ctx.unique_name("AmazonMSK_sim2real-")
    resp = secretsmanager.create_secret(
        Name=name,
        KmsKeyId=key_id,
        SecretString=json.dumps({"username": "sim2real-user", "password": "Sim2Real-Passw0rd!"}),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    secret_arn = resp["ARN"]
    ctx.on_cleanup(
        lambda: secretsmanager.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True)
    )
    return secret_arn


def _create_active_msk_cluster(ctx, *, sasl_scram: bool = False, timeout_s: float = 1800.0) -> str:
    kafka = ctx.client("kafka")
    _, subnets = _default_vpc_subnets(ctx, 2)
    versions = kafka.list_kafka_versions().get("KafkaVersions", [])
    kafka_version = next((v["Version"] for v in versions if v.get("Status") == "ACTIVE"), None)
    if not kafka_version and versions:
        kafka_version = versions[0]["Version"]
    if not kafka_version:
        kafka_version = "3.9.x"

    provisioned = {
        "BrokerNodeGroupInfo": {"InstanceType": "kafka.t3.small", "ClientSubnets": subnets},
        "KafkaVersion": kafka_version,
        "NumberOfBrokerNodes": len(subnets),
    }
    if sasl_scram:
        provisioned["ClientAuthentication"] = {"Sasl": {"Scram": {"Enabled": True}}}

    name = ctx.unique_name("sim2real-msk-")
    resp = kafka.create_cluster_v2(
        ClusterName=name, Provisioned=provisioned, Tags={"sim2real": "true"}
    )
    arn = resp["ClusterArn"]

    def _cleanup():
        try:
            info = kafka.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]
            if info["State"] != "DELETING":
                kafka.delete_cluster(ClusterArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    deadline = time.monotonic() + timeout_s
    state = "CREATING"
    while time.monotonic() < deadline:
        info = kafka.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]
        state = info["State"]
        if state in ("ACTIVE", "FAILED"):
            break
        time.sleep(2)
    if state != "ACTIVE":
        raise AssertionError(f"cluster did not reach ACTIVE within {timeout_s}s (state={state})")
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
