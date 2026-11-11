"""create-cluster-out-of-range-node-count-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-cluster-out-of-range-node-count-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCluster asking for 8 ml.p5.48xlarge nodes, whose account quota is 0, fails with
    ResourceLimitExceeded and the exact message and creates no cluster, while a one-node ml.t3.medium
    cluster is created and described with the ARN CreateCluster returned."""
    sm = ctx.client("sagemaker")
    role_arn = _create_sagemaker_role(ctx)

    bad_cluster_name = ctx.unique_name("sim2real-behav-cluster-bad-")
    code, message = _error(lambda: _retry_role_propagation(lambda: sm.create_cluster(
        ClusterName=bad_cluster_name,
        InstanceGroups=_slurm_instance_groups(role_arn, "ml.p5.48xlarge", 8),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )))
    assert code == "ResourceLimitExceeded", f"expected ResourceLimitExceeded, got {code!r}"
    expected_message = (
        "The account-level service limit 'ml.p5.48xlarge for cluster usage' is 0 Instances, "
        "with current utilization of 0 Instances and a request delta of 8 Instances. "
        "Please use AWS Service Quotas to request an increase for this quota. "
        "If AWS Service Quotas is not available, contact AWS support to request an increase "
        "for this quota."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: no cluster with that name was persisted
    describe_code, describe_message = _error(lambda: sm.describe_cluster(ClusterName=bad_cluster_name))
    assert describe_code == "ResourceNotFound", f"expected ResourceNotFound, got {describe_code!r}"
    expected_describe_message = f"Cluster with name {bad_cluster_name} not found"
    assert describe_message == expected_describe_message, (
        f"expected message {expected_describe_message!r}, got {describe_message!r}"
    )

    # positive control: a modest, commonly-quota-available node count is accepted
    good_cluster_name = ctx.unique_name("sim2real-behav-cluster-good-")
    create_resp = _retry_role_propagation(lambda: sm.create_cluster(
        ClusterName=good_cluster_name,
        InstanceGroups=_slurm_instance_groups(role_arn, "ml.t3.medium", 1),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    ))
    ctx.on_cleanup(lambda: _best_effort_delete_cluster(sm, good_cluster_name))

    # independent read at the destination: ClusterArn's suffix is an opaque cluster id, not the
    # cluster name, so the terminal assertion is DescribeCluster reporting the same name and ARN
    # CreateCluster just returned -- not a guess about the ARN's shape.
    describe_resp = sm.describe_cluster(ClusterName=good_cluster_name)
    assert describe_resp["ClusterName"] == good_cluster_name, (
        f"expected ClusterName {good_cluster_name!r}, got {describe_resp['ClusterName']!r}"
    )
    assert describe_resp["ClusterArn"] == create_resp["ClusterArn"], (
        f"expected DescribeCluster to report the same ARN CreateCluster returned, "
        f"got {describe_resp['ClusterArn']!r} vs {create_resp['ClusterArn']!r}"
    )


def _error(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected the call to raise a ClientError, it succeeded")


def _best_effort_delete_cluster(sm, cluster_name):
    # A cluster whose instance groups are still being created refuses DeleteCluster until they settle.
    deadline = time.monotonic() + 900.0
    while True:
        try:
            sm.delete_cluster(ClusterName=cluster_name)
            return
        except ClientError as exc:
            error = exc.response["Error"]
            code = error["Code"]
            if code == "ResourceNotFound":
                return
            busy = code == "ConflictException" or (
                code == "ValidationException" and "finish ongoing changes" in error.get("Message", "")
            )
            if not busy or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _slurm_instance_groups(role_arn, worker_instance_type, worker_instance_count):
    """A minimal valid HyperPod Slurm topology: one controller group plus one worker group.

    CreateCluster rejects any InstanceGroups list with no Controller SlurmConfig entry
    (ValidationException), so the group under test for out-of-range capacity must be paired with a
    controller group to reach the quota check at all.
    """
    return [
        {
            "InstanceGroupName": "sim2real-controller",
            "InstanceType": "ml.m5.xlarge",
            "InstanceCount": 1,
            "ExecutionRole": role_arn,
            "SlurmConfig": {"NodeType": "Controller"},
        },
        {
            "InstanceGroupName": "sim2real-quota-group",
            "InstanceType": worker_instance_type,
            "InstanceCount": worker_instance_count,
            "ExecutionRole": role_arn,
            "SlurmConfig": {"NodeType": "Compute"},
        },
    ]


def _retry_role_propagation(fn, deadline_s=60.0):
    """Retry while SageMaker still reports the freshly-created role as not yet assumable.

    IAM role visibility (get_role succeeding) does not imply the trust policy has propagated to
    SageMaker's HyperPod control plane yet. Real AWS surfaces that lag as a ValidationException
    reading "SageMaker HyperPod cannot assume the execution role ... Please ensure that the
    execution role allows the action sts:AssumeRole for the service principal
    sagemaker.amazonaws.com". Any other error, including a
    ValidationException with a different message and the ResourceLimitExceeded this check is
    asserting, is definitive and must not be retried away.
    """
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            err = exc.response["Error"]
            transient = (
                err["Code"] == "ValidationException"
                and "cannot assume the execution role" in err.get("Message", "")
            )
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


def _create_sagemaker_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-smrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sagemaker.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    deadline = time.monotonic() + 20.0
    while True:
        try:
            iam.get_role(RoleName=role_name)
            return role_arn
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(1.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
