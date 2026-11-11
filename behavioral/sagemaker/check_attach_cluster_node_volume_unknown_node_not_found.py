"""attach-cluster-node-volume-unknown-node-not-found."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "attach-cluster-node-volume-unknown-node-not-found"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AttachClusterNodeVolume with an unknown NodeId on a real HyperPod cluster is ResourceNotFound
    "Specified cluster node not found" and leaves the volume untouched, while a nonexistent
    ClusterArn gets a different not-found message naming the cluster.
    """
    sm = ctx.client("sagemaker")
    iam = ctx.client("iam")
    ec2 = ctx.client("ec2")

    role_name = ctx.unique_name("sim2real-sm-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "sagemaker.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)[
        "Role"
    ]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    # Teardowns run LIFO: register the role delete first so the policy detach runs before it.
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))

    cluster_name = ctx.unique_name("sim2real-behav-cl-")
    # The smallest cluster CreateCluster accepts: exactly one instance group, explicitly Slurm
    # (no orchestrator and no SlurmConfig is rejected). Retried, bounded, because a role IAM
    # just created is not immediately assumable by SageMaker.
    try:
        create_resp = _poll_create_cluster(
            sm,
            cluster_name=cluster_name,
            role_arn=role_arn,
            timeout_s=45.0,
            interval_s=5.0,
        )
    except ClientError as e:
        raise AssertionError(
            "this account/region rejects a minimal one-instance-group HyperPod cluster "
            f"outright ({e.response['Error']['Code']}: {e.response['Error']['Message']}); "
            "AttachClusterNodeVolume's precondition check needs at least this much of a "
            "real cluster to hold a genuine ClusterArn."
        )
    cluster_arn = create_resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_with_retry(sm, cluster_name))

    # A real EBS volume: a nonexistent VolumeId is rejected by EC2 validation before the
    # NodeId is looked up, which would mask the assertion below.
    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    real_volume_id = ec2.create_volume(
        AvailabilityZone=az,
        Size=1,
        VolumeType="gp3",
        TagSpecifications=[
            {"ResourceType": "volume", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-vol-")}]}
        ],
    )["VolumeId"]
    ctx.on_cleanup(lambda: ec2.delete_volume(VolumeId=real_volume_id))
    ec2.get_waiter("volume_available").wait(VolumeIds=[real_volume_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    fake_node_id = "i-00000000"
    code, message = _error(
        lambda: sm.attach_cluster_node_volume(
            ClusterArn=cluster_arn, NodeId=fake_node_id, VolumeId=real_volume_id
        )
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code!r}"
    expected = "Specified cluster node not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the volume we control was never touched by the rejected call
    vol_state = ec2.describe_volumes(VolumeIds=[real_volume_id])["Volumes"][0]["State"]
    assert vol_state == "available", f"expected volume to remain available, got {vol_state!r}"

    # effect absent: the cluster still reports no such node either
    node_code, node_message = _error(
        lambda: sm.describe_cluster_node(ClusterName=cluster_name, NodeId=fake_node_id)
    )
    assert node_code == "ResourceNotFound", f"expected ResourceNotFound, got {node_code!r}"
    expected_node = "Specified cluster node not found"
    assert node_message == expected_node, f"expected message {expected_node!r}, got {node_message!r}"

    # discriminating control: a totally nonexistent ClusterArn is refused with a DIFFERENT
    # not-found message, naming the cluster rather than the node -- a stub that returns one
    # answer regardless of which identifier is unknown fails this.
    bogus_cluster_arn = (
        f"arn:aws:sagemaker:{ctx.region}:{ctx.client('sts').get_caller_identity()['Account']}"
        f":cluster/{uuid.uuid4().hex[:12]}"
    )
    bogus_code, bogus_message = _error(
        lambda: sm.attach_cluster_node_volume(
            ClusterArn=bogus_cluster_arn, NodeId=fake_node_id, VolumeId=real_volume_id
        )
    )
    assert bogus_code == "ResourceNotFound", f"expected ResourceNotFound, got {bogus_code!r}"
    expected_bogus = "Specified cluster not found"
    assert bogus_message == expected_bogus, f"expected message {expected_bogus!r}, got {bogus_message!r}"
    assert bogus_message != message, "an unknown cluster and an unknown node on a real cluster must not collapse to one answer"

    # positive control: the real cluster resource itself is real and describable -- the
    # rejection above is read off its actual state, not a broken cluster or a failure to
    # reach the API at all.
    desc = sm.describe_cluster(ClusterName=cluster_name)
    assert desc["ClusterArn"] == cluster_arn, f"expected {cluster_arn!r}, got {desc['ClusterArn']!r}"
    assert desc["ClusterName"] == cluster_name, f"expected {cluster_name!r}, got {desc['ClusterName']!r}"
    assert desc["ClusterStatus"] in ("Creating", "InService", "Failed"), (
        f"unexpected ClusterStatus {desc['ClusterStatus']!r}"
    )


def _poll_create_cluster(sm, *, cluster_name, role_arn, timeout_s, interval_s):
    """Retry CreateCluster, bounded: a just-created IAM role is not immediately assumable by
    SageMaker, which surfaces as a transient ClientError with no distinct code."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return sm.create_cluster(
                ClusterName=cluster_name,
                InstanceGroups=[
                    {
                        "InstanceGroupName": "controller",
                        "InstanceType": "ml.c5.xlarge",
                        "InstanceCount": 1,
                        "ExecutionRole": role_arn,
                        "SlurmConfig": {"NodeType": "Controller"},
                    }
                ],
            )
        except ClientError as e:
            last_exc = e
            time.sleep(interval_s)
    raise last_exc


def _error(fn):
    """Return (code, message) of the call's ClientError; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_cluster_with_retry(sm, cluster_name, timeout_s=600.0, interval_s=2.0):
    """DeleteCluster refuses while the instance group is still Creating ("Please wait for instance
    group to finish ongoing changes"); retry on exactly that refusal and raise at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sm.delete_cluster(ClusterName=cluster_name)
            return
        except ClientError as e:
            err = e.response["Error"]
            if err["Code"] == "ResourceNotFound":
                return
            busy = (err["Code"] == "ValidationException"
                    and "finish ongoing changes" in err.get("Message", ""))
            if not busy or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
