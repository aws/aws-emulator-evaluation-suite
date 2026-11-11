"""scram-secrets-list-reflects-association-order."""
from __future__ import annotations

import json
import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scram-secrets-list-reflects-association-order"
GROUP = "ordering"
SERVICES = ["kafka"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After three sequential BatchAssociateScramSecret calls (one secret per call, in a
    known order), ListScramSecrets returns all three ARNs with no loss or duplicate on every one
    of repeated calls; AWS documents no order, so the listings are compared order-insensitively.
    """
    kafka = ctx.client("kafka")
    kms = ctx.client("kms")
    secretsmanager = ctx.client("secretsmanager")

    key_id = kms.create_key(
        Description="sim2real-behav-msk-scram-order",
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    secret_arns = [_create_scram_secret(ctx, secretsmanager, key_id) for _ in range(3)]

    _, subnet_ids, sg_id = _default_vpc_subnets(ctx)
    cluster_arn = _create_scram_cluster(ctx, subnet_ids, sg_id)

    for arn in secret_arns:
        resp = kafka.batch_associate_scram_secret(ClusterArn=cluster_arn, SecretArnList=[arn])
        assert resp.get("UnprocessedScramSecrets", []) == [], resp["UnprocessedScramSecrets"]
        _wait_secret_associated(kafka, cluster_arn, arn)

    listings = [_list_scram_secrets(kafka, cluster_arn) for _ in range(3)]
    for listing in listings:
        assert set(listing) == set(secret_arns), (
            f"ListScramSecrets lost or gained entries: expected {set(secret_arns)}, got {set(listing)}"
        )
        assert len(listing) == len(secret_arns), f"ListScramSecrets returned duplicates: {listing}"
    for listing in listings[1:]:
        assert listing == listings[0] or sorted(listing) == sorted(listings[0]), (
            f"repeated ListScramSecrets calls returned different secrets: {listings[0]} vs {listing}"
        )


def _random_password(n: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def _create_scram_secret(ctx, secretsmanager, key_id: str) -> str:
    name = ctx.unique_name("AmazonMSK_sim2real_")
    resp = secretsmanager.create_secret(
        Name=name,
        KmsKeyId=key_id,
        SecretString=json.dumps({"username": "sim2real-user", "password": _random_password()}),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    arn = resp["ARN"]
    ctx.on_cleanup(lambda: secretsmanager.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True))
    return arn


def _list_scram_secrets(kafka, cluster_arn):
    out = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = kafka.list_scram_secrets(ClusterArn=cluster_arn, **kwargs)
        out.extend(resp.get("SecretArnList", []))
        token = resp.get("NextToken")
        if not token:
            return out


def _wait_secret_associated(kafka, cluster_arn, secret_arn, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if secret_arn in _list_scram_secrets(kafka, cluster_arn):
            return
        time.sleep(interval_s)
    raise AssertionError("secret never showed up as associated")


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
    return active[0] if active else versions[-1]["Version"]


def _create_scram_cluster(ctx, subnet_ids, sg_id) -> str:
    kafka = ctx.client("kafka")
    name = ctx.unique_name("sim2real-scramorder-")
    version = _pick_kafka_version(kafka)
    resp = kafka.create_cluster(
        ClusterName=name,
        KafkaVersion=version,
        NumberOfBrokerNodes=len(subnet_ids),
        BrokerNodeGroupInfo={
            "InstanceType": "kafka.t3.small",
            "ClientSubnets": subnet_ids,
            "SecurityGroups": [sg_id],
        },
        ClientAuthentication={"Sasl": {"Scram": {"Enabled": True}}},
        EncryptionInfo={"EncryptionInTransit": {"ClientBroker": "TLS", "InCluster": True}},
        Tags={"sim2real:managed": "true"},
    )
    arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster(ctx, arn))
    _wait_cluster_state(ctx, arn, {"ACTIVE"}, timeout_s=1800)
    return arn


def _delete_cluster(ctx, arn: str) -> None:
    kafka = ctx.client("kafka")
    try:
        kafka.delete_cluster(ClusterArn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NotFoundException":
            return
        raise
    _wait_cluster_deleted(ctx, arn, timeout_s=1800)


def _wait_cluster_state(ctx, arn, target_states, timeout_s=1800.0, interval_s=20.0):
    kafka = ctx.client("kafka")
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
    raise AssertionError(f"cluster did not reach {target_states} within {timeout_s}s (last={last})")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
