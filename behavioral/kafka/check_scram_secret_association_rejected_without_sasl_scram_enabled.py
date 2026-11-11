"""scram-secret-association-rejected-without-sasl-scram-enabled."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scram-secret-association-rejected-without-sasl-scram-enabled"
GROUP = "e2e"
SERVICES = ["kafka"]

# Pinned rather than discovered via ListKafkaVersions: the newest ACTIVE version is KRaft-only and
# rejects the standard (non-Express) broker instance type this check uses (real AWS: "Standard
# instance types are not supported for Kafka version 4.2.x.kraft").
_KAFKA_VERSION = "3.9.x"


@tags("axis:rejection", "cap:c1", "cap:c4", "plane:control")
def run(ctx) -> None:
    """BatchAssociateScramSecret fails a secret against a cluster with SASL/SCRAM turned off;
    the secret is not associated; enabling SASL/SCRAM on the same cluster and retrying succeeds."""
    kafka = ctx.client("kafka")
    kms = ctx.client("kms")
    secretsmanager = ctx.client("secretsmanager")

    subnet_ids, sg_id = _two_az_subnets(ctx)
    kafka_version = _KAFKA_VERSION

    # Setup: a cluster with TLS-mutual-off, unauthenticated-only access (no SASL/SCRAM).
    name = ctx.unique_name("sim2real-msk-noscram-")
    create_resp = kafka.create_cluster_v2(
        ClusterName=name,
        Provisioned={
            "BrokerNodeGroupInfo": {
                "InstanceType": "kafka.m5.large",
                "ClientSubnets": subnet_ids,
                "SecurityGroups": [sg_id],
            },
            "KafkaVersion": kafka_version,
            "NumberOfBrokerNodes": len(subnet_ids),
            "ClientAuthentication": {"Unauthenticated": {"Enabled": True}},
            "EncryptionInfo": {"EncryptionInTransit": {"ClientBroker": "TLS_PLAINTEXT"}},
        },
        Tags={"sim2real:managed": "true"},
    )
    cluster_arn = create_resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(kafka, cluster_arn))
    cluster_info = _wait_cluster_active(kafka, cluster_arn)
    current_version = cluster_info["CurrentVersion"]

    key_arn = kms.create_key(
        Description="sim2real msk scram secret key",
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
    )["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7))
    secret_name = f"AmazonMSK_{ctx.unique_name('sim2real')}"
    secret_arn = secretsmanager.create_secret(
        Name=secret_name,
        KmsKeyId=key_arn,
        SecretString=json.dumps({"username": "sim2realuser", "password": "Sim2Real-Pw-9!"}),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["ARN"]
    ctx.on_cleanup(lambda: secretsmanager.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    # Break exactly one thing: try to associate the secret while SASL/SCRAM is not enabled. Real MSK
    # rejects the whole call with BadRequestException here -- it does not report the secret as
    # UnprocessedScramSecrets in a 200.
    try:
        assoc = kafka.batch_associate_scram_secret(ClusterArn=cluster_arn, SecretArnList=[secret_arn])
    except ClientError as exc:
        error = exc.response.get("Error", {})
        code = error.get("Code")
        message = error.get("Message", "")
        assert code == "BadRequestException", f"expected BadRequestException, got {code}: {message}"
        assert "SASL/SCRAM" in message, f"expected a SASL/SCRAM-specific message, got: {message!r}"
        assert message == "SASL/SCRAM client authentication must be enabled for the cluster.", (
            f"BatchAssociateScramSecret rejection message: {message!r}"
        )
    else:
        raise AssertionError(
            f"expected BatchAssociateScramSecret to be rejected while SASL/SCRAM is disabled, "
            f"but it succeeded: {assoc!r}"
        )

    # effect absent: the secret is not associated with the cluster
    associated = kafka.list_scram_secrets(ClusterArn=cluster_arn).get("SecretArnList", [])
    assert secret_arn not in associated, "secret was associated despite SASL/SCRAM being disabled"

    # positive control: turn on SASL/SCRAM via UpdateSecurity, then the same association succeeds
    security_update = kafka.update_security(
        ClusterArn=cluster_arn,
        CurrentVersion=current_version,
        ClientAuthentication={"Sasl": {"Scram": {"Enabled": True}}},
    )
    _wait_cluster_operation_completed(kafka, security_update["ClusterOperationArn"])
    _wait_cluster_active(kafka, cluster_arn)

    assoc2 = kafka.batch_associate_scram_secret(ClusterArn=cluster_arn, SecretArnList=[secret_arn])
    assert assoc2.get("UnprocessedScramSecrets", []) == [], (
        f"secret association still failed after enabling SASL/SCRAM: {assoc2!r}"
    )
    associated2 = kafka.list_scram_secrets(ClusterArn=cluster_arn).get("SecretArnList", [])
    assert secret_arn in associated2, (
        f"expected {secret_arn} in ListScramSecrets after enabling SASL/SCRAM, got {associated2!r}"
    )


def _two_az_subnets(ctx):
    """Two subnets of the run's shared network in distinct AZs, and the network's security group."""
    net = ctx.network()
    if len(net.subnets) < 2:
        raise AssertionError(f"the shared network has subnets in {len(net.subnets)} Availability Zones, need 2")
    return net.subnet_ids[:2], net.security_group_id


def _wait_cluster_active(kafka, cluster_arn, timeout_s=1800.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    info = None
    while time.monotonic() < deadline:
        info = kafka.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]
        if info["State"] == "ACTIVE":
            return info
        if info["State"] == "FAILED":
            raise AssertionError(f"cluster {cluster_arn} entered FAILED state")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_arn} did not reach ACTIVE within {timeout_s}s, last state {info}")


def _wait_cluster_operation_completed(kafka, operation_arn, timeout_s=1800.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = kafka.describe_cluster_operation_v2(ClusterOperationArn=operation_arn)["ClusterOperationInfo"][
            "OperationState"
        ]
        if state in ("UPDATE_COMPLETE",):
            return
        if state in ("UPDATE_FAILED",):
            raise AssertionError(f"cluster operation {operation_arn} failed")
        time.sleep(interval_s)
    raise AssertionError(f"cluster operation {operation_arn} did not complete within {timeout_s}s, last {state!r}")


def _delete_cluster_and_wait(kafka, cluster_arn, timeout_s=1800.0, interval_s=20.0):
    try:
        kafka.delete_cluster(ClusterArn=cluster_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            kafka.describe_cluster_v2(ClusterArn=cluster_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise
            return
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
