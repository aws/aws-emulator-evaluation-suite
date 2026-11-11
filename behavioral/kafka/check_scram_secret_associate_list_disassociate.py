"""scram-secret-associate-list-disassociate."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scram-secret-associate-list-disassociate"
GROUP = 'cluster-lifecycle'
SERVICES = ['kafka']

_DEFAULT_KAFKA_VERSION = "3.9.x"
_PROVISIONED_INSTANCE_TYPE = "kafka.m5.large"


def _err(fn):
    """Call fn(); return the botocore Error.Code if a ClientError is raised, else None."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return None


def _discover_network(ctx, minimum_subnets=2):
    """The run's shared network (ctx.network()): its VPC, up to three of its subnets in distinct
    availability zones, and the VPC's default security group."""
    net = ctx.network()
    zones = net.availability_zones
    assert len(zones) >= minimum_subnets, (
        f"the shared network has subnets in {len(zones)} availability zones, need {minimum_subnets}"
    )
    return net.vpc_id, [net.subnets[az] for az in zones][:3], net.security_group_id


def _create_cluster_network(ctx, num_subnets=2):
    """Shared per-check discovered network (memoized on ctx)."""
    if not hasattr(ctx, "_kafka_net"):
        ctx._kafka_net = _discover_network(ctx, minimum_subnets=2)
    vpc_id, subnet_ids, sg_id = ctx._kafka_net
    if num_subnets > len(subnet_ids):
        raise AssertionError(f"discovered network only has {len(subnet_ids)} subnets, need {num_subnets}")
    return vpc_id, subnet_ids[:num_subnets], sg_id


def _provisioned_body(subnet_ids, sg_id, num_brokers=2, kafka_version=_DEFAULT_KAFKA_VERSION,
                      instance_type=_PROVISIONED_INSTANCE_TYPE, volume_size=10):
    broker_info = {
        "InstanceType": instance_type,
        "ClientSubnets": subnet_ids,
        "StorageInfo": {"EbsStorageInfo": {"VolumeSize": volume_size}},
    }
    if sg_id:
        broker_info["SecurityGroups"] = [sg_id]
    return {
        "BrokerNodeGroupInfo": broker_info,
        "KafkaVersion": kafka_version,
        "NumberOfBrokerNodes": num_brokers,
    }


def _create_scram_cluster(ctx, msk, name_prefix="scram-"):
    """Create a PROVISIONED cluster with SASL/SCRAM client authentication enabled.

    Returns immediately in CREATING; registers DeleteCluster teardown. SCRAM secret
    association requires the cluster to have SASL/SCRAM enabled and to be ACTIVE.
    """
    name = ctx.unique_name("sim2real-behav-" + name_prefix)
    _, subnet_ids, sg_id = _create_cluster_network(ctx, num_subnets=2)
    prov = _provisioned_body(subnet_ids, sg_id, num_brokers=2)
    prov["ClientAuthentication"] = {"Sasl": {"Scram": {"Enabled": True}}}
    prov["EncryptionInfo"] = {
        "EncryptionInTransit": {"ClientBroker": "TLS", "InCluster": True}
    }
    try:
        resp = msk.create_cluster_v2(
            ClusterName=name, Provisioned=prov, Tags={"sim2real:managed": "true"}
        )
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        raise AssertionError(
            f"could not create a SASL/SCRAM MSK cluster for this check ({code}: {exc})"
        ) from exc
    arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_when_settled(msk, arn))
    return arn


def _delete_cluster_when_settled(msk, arn, timeout_s=1700.0, interval_s=15.0):
    """DeleteCluster refuses a cluster that is CREATING or UPDATING, so wait for ACTIVE or FAILED first,
    then wait until DescribeClusterV2 returns NotFoundException."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            state = msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["State"]
            if state in ("ACTIVE", "FAILED"):
                msk.delete_cluster(ClusterArn=arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"cluster {arn} still {state} after {timeout_s:.0f}s; it was not deleted")
        time.sleep(interval_s)


def _wait_cluster_active(ctx, msk, arn):
    """Wait until the cluster is ACTIVE. Real MSK PROVISIONED clusters routinely take 20-40+ minutes
    to settle, with real observed variance above 1800s, so the budget below matches that convention
    on every target."""
    budget_s = 2700
    interval_s = 2
    deadline = time.monotonic() + budget_s
    last = None
    while time.monotonic() < deadline:
        last = msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["State"]
        if last == "ACTIVE":
            return
        if last == "FAILED":
            raise AssertionError("cluster reached FAILED instead of ACTIVE")
        time.sleep(interval_s)
    raise AssertionError(
        f"cluster not ACTIVE within {budget_s}s (last state {last}); "
        "MSK provisioning exceeds the per-check budget"
    )


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """On a SASL/SCRAM ACTIVE cluster, BatchAssociateScramSecret returns no UnprocessedScramSecrets and
    the secret appears in ListScramSecrets; BatchDisassociateScramSecret removes it again."""
    msk = ctx.client("kafka")
    sm = ctx.client("secretsmanager")
    kms = ctx.client("kms")
    arn = _create_scram_cluster(ctx, msk)
    _wait_cluster_active(ctx, msk, arn)

    # MSK refuses a secret encrypted with the default aws/secretsmanager key
    # (InvalidSecretArn: "You can't use this secret with Amazon MSK") -- a
    # customer-managed key is required.
    key_id = kms.create_key(Description="sim2real-behav-msk-scram")["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    secret = sm.create_secret(
        Name=ctx.unique_name("AmazonMSK_sim2real-behav-"),
        KmsKeyId=key_id,
        SecretString=json.dumps({"username": "user", "password": "S3cretPassw0rd!"}),
    )
    secret_arn = secret["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    resp = msk.batch_associate_scram_secret(ClusterArn=arn, SecretArnList=[secret_arn])
    assert resp.get("UnprocessedScramSecrets", []) == [], f"expected no unprocessed secrets, got {resp}"

    listed = _poll_until(
        lambda: msk.list_scram_secrets(ClusterArn=arn)["SecretArnList"],
        lambda lst: secret_arn in lst,
        description="secret appears in ListScramSecrets",
    )
    assert secret_arn in listed, listed

    resp2 = msk.batch_disassociate_scram_secret(ClusterArn=arn, SecretArnList=[secret_arn])
    assert resp2.get("UnprocessedScramSecrets", []) == [], f"expected no unprocessed secrets, got {resp2}"

    remaining = _poll_until(
        lambda: msk.list_scram_secrets(ClusterArn=arn)["SecretArnList"],
        lambda lst: secret_arn not in lst,
        description="secret removed from ListScramSecrets",
    )
    assert secret_arn not in remaining, remaining

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
