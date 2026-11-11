"""batch-add-cluster-nodes-wrong-state-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "batch-add-cluster-nodes-wrong-state-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


_CLUSTER_INSERVICE_TIMEOUT_S = 1800

# IAM role trust policies and managed-policy attachments are eventually consistent: a
# dependent service can reject a call made against a just-created role with one of these
# codes before propagation finishes. Retry the dependent call itself (bounded, with a
# deadline) instead of sleeping blind before making it.
_ROLE_NOT_READY_CODES = {
    "InvalidParameterException",
    "AccessDenied",
    "AccessDeniedException",
    "ValidationException",
}


def _retry_while_role_not_ready(fn, *, timeout_s=180, interval_s=15):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in _ROLE_NOT_READY_CODES or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BatchAddClusterNodes against a HyperPod cluster that is Deleting is rejected with
    ValidationException naming the termination state and leaves the instance group's
    target count unchanged; the same call must succeed first while InService."""
    sm = ctx.client("sagemaker")
    exec_role_arn = _create_sagemaker_role(ctx)

    cluster_name = ctx.unique_name("sim2real-hp-")
    created = _retry_while_role_not_ready(
        lambda: sm.create_cluster(
            ClusterName=cluster_name,
            Orchestrator={"Slurm": {}},
            InstanceGroups=[
                {
                    "InstanceGroupName": "controller",
                    "InstanceType": "ml.t3.medium",
                    "InstanceCount": 1,
                    "ExecutionRole": exec_role_arn,
                    "SlurmConfig": {"NodeType": "Controller"},
                },
                {
                    "InstanceGroupName": "workers",
                    "InstanceType": "ml.t3.medium",
                    "InstanceCount": 0,
                    "ExecutionRole": exec_role_arn,
                    "SlurmConfig": {"NodeType": "Compute", "PartitionNames": ["workers"]},
                },
            ],
            Tags=[{"Key": "sim2real", "Value": "1"}],
        )
    )
    cluster_arn = created["ClusterArn"]
    ctx.on_cleanup(
        _teardown(
            lambda: sm.delete_cluster(ClusterName=cluster_name),
            "ResourceNotFound",
            "ValidationException",
        )
    )
    cluster_status = _poll_until(
        lambda: sm.describe_cluster(ClusterName=cluster_name)["ClusterStatus"],
        lambda s: s in ("InService", "Failed"),
        timeout_s=_CLUSTER_INSERVICE_TIMEOUT_S,
        interval_s=20,
    )
    if cluster_status != "InService":
        failure_message = sm.describe_cluster(ClusterName=cluster_name).get("FailureMessage")
        raise AssertionError(
            f"HyperPod cluster never reached InService (status={cluster_status}, "
            f"FailureMessage={failure_message!r}); likely no HyperPod capacity "
            "for ml.t3.medium in this account/region",
        )

    # (c) positive control: BatchAddClusterNodes succeeds while the cluster is
    # InService -- assert on the response body, not just the absence of an error.
    add_response = sm.batch_add_cluster_nodes(
        ClusterName=cluster_name,
        NodesToAdd=[{"InstanceGroupName": "workers", "IncrementTargetCountBy": 1}],
    )
    successful = add_response.get("Successful", [])
    assert any(s["InstanceGroupName"] == "workers" for s in successful), (
        f"expected a successful node addition for 'workers', got {add_response}"
    )
    assert not add_response.get("Failed"), add_response.get("Failed")

    # Negative: begin deleting the cluster, then try to add nodes to it.
    sm.delete_cluster(ClusterName=cluster_name)
    deleting = sm.describe_cluster(ClusterName=cluster_name)
    assert deleting["ClusterStatus"] == "Deleting", (
        f"expected ClusterStatus Deleting right after DeleteCluster, got {deleting['ClusterStatus']}"
    )
    before_target_count = _target_count(deleting, "workers")
    code, message = _error_response(
        lambda: sm.batch_add_cluster_nodes(
            ClusterName=cluster_name,
            NodesToAdd=[{"InstanceGroupName": "workers", "IncrementTargetCountBy": 1}],
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message}"
    expected_message = f"Cluster {cluster_arn} is in a termination state that cannot be modified."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # (b) effect absent: the rejected add did not change the instance group's target
    # node count (checked if the cluster is still describable mid-deletion; if it has
    # already fully disappeared there is nothing left that could have been mutated).
    from botocore.exceptions import ClientError

    try:
        described_after = sm.describe_cluster(ClusterName=cluster_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise
        described_after = None
    if described_after is not None:
        after_target_count = _target_count(described_after, "workers")
        assert after_target_count == before_target_count, (
            "rejected BatchAddClusterNodes call changed the target node count: "
            f"{before_target_count} -> {after_target_count}"
        )


# ===== helpers =====

def _target_count(described_cluster, instance_group_name):
    for group in described_cluster.get("InstanceGroups", []):
        if group.get("InstanceGroupName") == instance_group_name:
            return group.get("TargetCount", group.get("CurrentCount"))
    raise AssertionError(f"instance group {instance_group_name} not found in DescribeCluster")


def _error_response(fn):
    """Return the code and message of a rejected call; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            return value
        time.sleep(interval_s)
        value = probe()
    return value


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only the resource's own
    not-found codes mean it is already gone."""
    from botocore.exceptions import ClientError

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_sagemaker_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-smrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
