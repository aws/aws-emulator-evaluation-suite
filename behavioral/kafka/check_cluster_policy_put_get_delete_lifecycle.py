"""cluster-policy-put-get-delete-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-policy-put-get-delete-lifecycle"
GROUP = 'cluster-lifecycle'
SERVICES = ['kafka']

_DEFAULT_KAFKA_VERSION = "3.9.x"
_PROVISIONED_INSTANCE_TYPE = "kafka.m5.large"


def _err(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises.

    Raises if the call succeeds, so an emulator that accepts what AWS refuses fails
    loudly instead of reading as a code mismatch."""
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {resp!r}")


def _account_id(ctx):
    if not hasattr(ctx, "_kafka_account_id"):
        ctx._kafka_account_id = ctx.client("sts").get_caller_identity()["Account"]
    return ctx._kafka_account_id


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


def _create_basic_cluster(ctx, msk, num_brokers=2, kafka_version=_DEFAULT_KAFKA_VERSION,
                          name_prefix="cluster-", tags=None):
    """Create a PROVISIONED cluster (returns immediately, state CREATING). Registers
    DeleteCluster teardown that waits for the cluster to settle. Returns (arn, name, subnet_ids, sg_id)."""
    name = ctx.unique_name("sim2real-behav-" + name_prefix)
    _, subnet_ids, sg_id = _create_cluster_network(ctx, num_subnets=2)
    kwargs = {
        "ClusterName": name,
        "Provisioned": _provisioned_body(
            subnet_ids, sg_id, num_brokers=num_brokers, kafka_version=kafka_version
        ),
        "Tags": {"sim2real:managed": "true", **(tags or {})},
    }
    try:
        resp = msk.create_cluster_v2(**kwargs)
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        raise AssertionError(
            f"could not create an MSK cluster for this check ({code}: {exc}); "
            f"network used: vpc subnets={subnet_ids} sg={sg_id}"
        ) from exc
    arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_when_settled(msk, arn))
    return arn, name, subnet_ids, sg_id


def _delete_cluster_when_settled(msk, arn, timeout_s=1740.0, interval_s=2.0):
    """DeleteCluster refuses a cluster that is CREATING or UPDATING, so wait for ACTIVE or FAILED,
    delete it, then wait until the cluster is gone."""
    deadline = time.monotonic() + timeout_s
    deleted = False
    while True:
        try:
            state = msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["State"]
            if state in ("ACTIVE", "FAILED") and not deleted:
                msk.delete_cluster(ClusterArn=arn)
                deleted = True
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"cluster {arn} still {state} after {timeout_s:.0f}s; it was not deleted")
        time.sleep(interval_s)


def _wait_cluster_active(msk, arn):
    """Wait until the cluster is ACTIVE. PROVISIONED MSK clusters of this shape take on the
    order of 20-30 minutes on AWS, so the deadline is 45 minutes."""
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


def _policy_doc(account_id, cluster_arn):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "sim2realAllowDescribe",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "kafka:DescribeCluster",
                    "Resource": cluster_arn,
                }
            ],
        }
    )


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """On an ACTIVE cluster GetClusterPolicy 404s before any policy, returns the document verbatim after
    PutClusterPolicy, and 404s again after DeleteClusterPolicy.
    """
    msk = ctx.client("kafka")
    arn, _name, _subnets, _sg = _create_basic_cluster(ctx, msk, name_prefix="policy-")
    _wait_cluster_active(msk, arn)

    before, before_msg = _err(lambda: msk.get_cluster_policy(ClusterArn=arn))
    assert before == "NotFoundException", f"expected NotFoundException before any policy, got {before}"
    assert before_msg == "The requested resource doesn\u2019t exist.", before_msg

    policy = _policy_doc(_account_id(ctx), arn)
    msk.put_cluster_policy(ClusterArn=arn, Policy=policy)

    got = msk.get_cluster_policy(ClusterArn=arn)
    assert json.loads(got["Policy"]) == json.loads(policy), got

    msk.delete_cluster_policy(ClusterArn=arn)
    after, after_msg = _err(lambda: msk.get_cluster_policy(ClusterArn=arn))
    assert after == "NotFoundException", f"expected NotFoundException after delete, got {after}"
    assert after_msg == "The requested resource doesn\u2019t exist.", after_msg

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
