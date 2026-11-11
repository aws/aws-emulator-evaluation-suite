"""replicator-same-source-target-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "replicator-same-source-target-rejected"
GROUP = 'overly-permissive'
SERVICES = ['kafka']


def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) it raises.

    A call that succeeds is itself the failure: raise AssertionError rather than return a code.
    """
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _wait_replicator_settled(msk, arn, *, timeout_s=1500, interval_s=15):
    """Poll DescribeReplicator until it leaves CREATING; raise on timeout. Returns the response."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = msk.describe_replicator(ReplicatorArn=arn)
        if last["ReplicatorState"] != "CREATING":
            return last
        time.sleep(interval_s)
    raise AssertionError(f"replicator {arn} still CREATING after {timeout_s}s")


def _account_id(ctx):
    if not hasattr(ctx, "_kafka_account_id"):
        ctx._kafka_account_id = ctx.client("sts").get_caller_identity()["Account"]
    return ctx._kafka_account_id


def _region(ctx):
    return getattr(ctx, "region", None) or "us-west-2"


def _bogus_cluster_arn(ctx):
    """A well-formed MSK cluster ARN, in this account, that cannot exist."""
    name = ctx.unique_name("sim2real-behav-ghost-cluster-")
    return f"arn:aws:kafka:{_region(ctx)}:{_account_id(ctx)}:cluster/{name}/{uuid.uuid4()}-2"


# Well-formed but nonexistent EC2 ids: real MSK validates the referenced clusters ASYNCHRONOUSLY, so
# a well-formed-but-nonexistent pair of *distinct* cluster ARNs is accepted without provisioning any
# cluster or VPC -- which is what makes the same-source-target invariant testable in isolation from
# cluster/network resolution.
_UNKNOWN_SUBNET_IDS = ["subnet-0a1b2c3d4e5f60718", "subnet-0a1b2c3d4e5f60719"]
_UNKNOWN_SECURITY_GROUP_IDS = ["sg-0a1b2c3d4e5f6071a"]


def _cluster_ref(arn):
    return {
        "AmazonMskCluster": {"MskClusterArn": arn},
        "VpcConfig": {"SubnetIds": _UNKNOWN_SUBNET_IDS, "SecurityGroupIds": _UNKNOWN_SECURITY_GROUP_IDS},
    }


def _replicator_kwargs(ctx, name, source_arn, target_arn, role_arn):
    return {
        "ReplicatorName": name,
        "ServiceExecutionRoleArn": role_arn,
        "KafkaClusters": [_cluster_ref(source_arn), _cluster_ref(target_arn)],
        "ReplicationInfoList": [
            {
                "SourceKafkaClusterArn": source_arn,
                "TargetKafkaClusterArn": target_arn,
                "TargetCompressionType": "NONE",
                "TopicReplication": {"TopicsToReplicate": [".*"]},
                "ConsumerGroupReplication": {"ConsumerGroupsToReplicate": [".*"]},
            }
        ],
    }


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateReplicator with source equal to target fails with BadRequestException and its exact message
    and leaves no replicator, while the same call with two distinct clusters returns CREATING and settles
    FAILED with the expected StateInfo."""
    msk = ctx.client("kafka")
    role_arn = f"arn:aws:iam::{_account_id(ctx)}:role/{ctx.unique_name('sim2real-behav-replicator-role-')}"

    control_name = ctx.unique_name("sim2real-behav-replicator-ctrl-")
    control_source, control_target = _bogus_cluster_arn(ctx), _bogus_cluster_arn(ctx)
    try:
        control_resp = msk.create_replicator(
            **_replicator_kwargs(ctx, control_name, control_source, control_target, role_arn)
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        raise AssertionError(
            "positive control failed: CreateReplicator with distinct cluster refs was "
            f"rejected ({code}); a same-source-target rejection would not be separable "
            "from a globally broken CreateReplicator call"
        ) from exc
    control_arn = control_resp["ReplicatorArn"]
    ctx.on_cleanup(lambda _a=control_arn: msk.delete_replicator(ReplicatorArn=_a))
    assert control_resp["ReplicatorState"] == "CREATING", control_resp["ReplicatorState"]
    assert control_arn.startswith("arn:aws:kafka:"), control_arn

    same_arn = _bogus_cluster_arn(ctx)
    replicator_name = ctx.unique_name("sim2real-behav-replicator-same-")
    created = {}

    def attempt():
        created["resp"] = msk.create_replicator(
            **_replicator_kwargs(ctx, replicator_name, same_arn, same_arn, role_arn)
        )
        # Never leak a replicator if AWS ever starts accepting this.
        arn = created["resp"].get("ReplicatorArn")
        if arn:
            ctx.on_cleanup(lambda _a=arn: msk.delete_replicator(ReplicatorArn=_a))
        return created["resp"]

    code, message = _err(attempt)
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    expected = "Kafka cluster list contains duplicate cluster ARNs. Please ensure all the cluster ARNs are unique."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    names = [r.get("ReplicatorName") for r in msk.list_replicators().get("Replicators", [])]
    assert replicator_name not in names, names

    # The control references clusters that do not exist, so it settles FAILED; DeleteReplicator
    # refuses a CREATING replicator, so the settle also lets cleanup remove it.
    settled = _wait_replicator_settled(msk, control_arn)
    assert settled["ReplicatorState"] == "FAILED", settled["ReplicatorState"]
    expected_info = {
        "Code": "InvalidInput.InvalidKafkaCluster",
        "Message": f"The specified Amazon MSK Cluster does not exist. Cluster ARN: {control_source}",
    }
    assert settled.get("StateInfo") == expected_info, settled.get("StateInfo")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
