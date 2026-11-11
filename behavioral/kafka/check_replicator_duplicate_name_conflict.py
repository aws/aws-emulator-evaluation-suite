"""replicator-duplicate-name-conflict."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "replicator-duplicate-name-conflict"
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


def _delete_replicator_retrying(msk, arn, *, timeout_s=300, interval_s=2):
    """DeleteReplicator, retried while MSK refuses it with BadRequestException because the
    replicator is still CREATING; not-found is done, anything else (or the deadline) raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            msk.delete_replicator(ReplicatorArn=arn)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NotFoundException":
                return
            if code != "BadRequestException" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _account_id(ctx):
    if not hasattr(ctx, "_kafka_account_id"):
        ctx._kafka_account_id = ctx.client("sts").get_caller_identity()["Account"]
    return ctx._kafka_account_id


def _region(ctx):
    return getattr(ctx, "region", None) or "us-west-2"


def _bogus_cluster_arn(ctx):
    name = ctx.unique_name("sim2real-behav-ghost-cluster-")
    return f"arn:aws:kafka:{_region(ctx)}:{_account_id(ctx)}:cluster/{name}/{uuid.uuid4()}-2"


# Well-formed but nonexistent EC2 ids: real MSK validates the referenced clusters
# ASYNCHRONOUSLY, so a replicator against ghost clusters is accepted (goes
# CREATING then FAILED) -- which is what makes the duplicate-name contract
# reachable without provisioning a cluster.
_UNKNOWN_SUBNET_IDS = ["subnet-0a1b2c3d4e5f60718", "subnet-0a1b2c3d4e5f60719"]
_UNKNOWN_SECURITY_GROUP_IDS = ["sg-0a1b2c3d4e5f6071a"]


def _replicator_kwargs(ctx, name):
    source_arn = _bogus_cluster_arn(ctx)
    target_arn = _bogus_cluster_arn(ctx)
    cluster = lambda arn: {  # noqa: E731
        "AmazonMskCluster": {"MskClusterArn": arn},
        "VpcConfig": {"SubnetIds": _UNKNOWN_SUBNET_IDS, "SecurityGroupIds": _UNKNOWN_SECURITY_GROUP_IDS},
    }
    return {
        "ReplicatorName": name,
        "ServiceExecutionRoleArn": f"arn:aws:iam::{_account_id(ctx)}:role/{ctx.unique_name('rrole-')}",
        "KafkaClusters": [cluster(source_arn), cluster(target_arn)],
        "ReplicationInfoList": [
            {
                "SourceKafkaClusterArn": source_arn,
                "TargetKafkaClusterArn": target_arn,
                "TargetCompressionType": "NONE",
                "TopicReplication": {"TopicsToReplicate": ["sim2real-behav-.*"]},
                "ConsumerGroupReplication": {"ConsumerGroupsToReplicate": ["sim2real-behav-.*"]},
            }
        ],
        "Tags": {"sim2real:managed": "true"},
    }


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateReplicator with the same ReplicatorName is rejected with ConflictException and
    ListReplicators shows exactly one replicator of that name; MSK validates the ghost cluster ARNs
    asynchronously, so the first create is accepted and later settles FAILED."""
    msk = ctx.client("kafka")
    name = ctx.unique_name("sim2real-behav-rep-dup-")

    first_kwargs = _replicator_kwargs(ctx, name)
    first_source = first_kwargs["ReplicationInfoList"][0]["SourceKafkaClusterArn"]
    try:
        first = msk.create_replicator(**first_kwargs)
    except ClientError as exc:
        raise AssertionError(
            "environment does not accept an async CreateReplicator against ghost clusters: "
            f"{exc.response.get('Error', {}).get('Code')}"
        ) from exc
    replicator_arn = first["ReplicatorArn"]
    ctx.on_cleanup(lambda _a=replicator_arn: _delete_replicator_retrying(msk, _a))
    assert first["ReplicatorState"] == "CREATING", first["ReplicatorState"]
    assert replicator_arn.startswith("arn:aws:kafka:"), replicator_arn

    dup_attempts = []

    def _dup_attempt():
        resp = msk.create_replicator(**_replicator_kwargs(ctx, name))
        dup_attempts.append(resp)
        return resp

    def _dup_attempt_tracked():
        try:
            return _dup_attempt()
        finally:
            # An over-permissive target that actually creates a second replicator here must not
            # leak it: register cleanup for anything a duplicate attempt managed to create.
            for resp in dup_attempts:
                arn = resp.get("ReplicatorArn")
                if arn:
                    ctx.on_cleanup(lambda _a=arn: _delete_replicator_retrying(msk, _a))
            dup_attempts.clear()

    expected_message = "A resource with this name already exists."
    for attempt in ("duplicate", "duplicate retry"):
        dup_code, dup_message = _err(_dup_attempt_tracked)
        assert dup_code == "ConflictException", f"{attempt}: expected ConflictException, got {dup_code!r}"
        assert dup_message == expected_message, (
            f"{attempt}: expected message {expected_message!r}, got {dup_message!r}"
        )

    listed = [
        r for r in msk.list_replicators(ReplicatorNameFilter=name).get("Replicators", [])
        if r.get("ReplicatorName") == name
    ]
    assert len(listed) == 1, f"expected exactly 1 replicator named {name}, got {listed}"

    # The replicator references clusters that do not exist, so it settles FAILED; DeleteReplicator
    # refuses a CREATING replicator, so the settle also lets cleanup remove it.
    described = _wait_replicator_settled(msk, replicator_arn)
    assert described["ReplicatorName"] == name, described["ReplicatorName"]
    assert described["ReplicatorState"] == "FAILED", described["ReplicatorState"]
    expected_info = {
        "Code": "InvalidInput.InvalidKafkaCluster",
        "Message": f"The specified Amazon MSK Cluster does not exist. Cluster ARN: {first_source}",
    }
    assert described.get("StateInfo") == expected_info, described.get("StateInfo")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
