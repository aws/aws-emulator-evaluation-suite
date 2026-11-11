"""attach-cluster-node-volume-cluster-not-found."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "attach-cluster-node-volume-cluster-not-found"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AttachClusterNodeVolume with a real EBS volume and a nonexistent cluster fails with
    ResourceNotFound and DescribeCluster confirms the cluster absent, each with its exact message,
    while a malformed NodeId on the same call fails with ValidationException and its exact message."""
    sm = ctx.client("sagemaker")
    ec2 = ctx.client("ec2")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

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

    cluster_arn = f"arn:aws:sagemaker:{ctx.region}:{account_id}:cluster/{uuid.uuid4().hex[:12]}"
    node_id = f"i-{uuid.uuid4().hex[:17]}"

    code, msg = _error_code_and_msg(
        lambda: sm.attach_cluster_node_volume(ClusterArn=cluster_arn, NodeId=node_id, VolumeId=real_volume_id)
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code!r}: {msg!r}"
    expected = "ClusterNotExistsException: Specified cluster not found"
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    # effect absent: the cluster is independently confirmed not to exist, via a
    # different operation than the attach call that was rejected above.
    describe_code, describe_msg = _error_code_and_msg(lambda: sm.describe_cluster(ClusterName=cluster_arn))
    assert describe_code == "ResourceNotFound", f"expected ResourceNotFound, got {describe_code!r}: {describe_msg!r}"
    expected_describe = "ClusterNotExistsException: Specified cluster not found"
    assert describe_msg == expected_describe, f"expected message {expected_describe!r}, got {describe_msg!r}"

    # discriminating control: the same nonexistent cluster with a NodeId that fails the node-id shape
    # is rejected with ValidationException, not ResourceNotFound.
    malformed_code, malformed_msg = _error_code_and_msg(
        lambda: sm.attach_cluster_node_volume(
            ClusterArn=cluster_arn, NodeId="not-a-real-node-id", VolumeId=real_volume_id
        )
    )
    assert malformed_code == "ValidationException", (
        f"expected ValidationException, got {malformed_code!r}: {malformed_msg!r}"
    )
    expected_malformed = (
        "1 validation error detected: Value 'not-a-real-node-id' at 'nodeId' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: i-[a-f0-9]{8}(?:[a-f0-9]{9})?"
    )
    assert malformed_msg == expected_malformed, f"expected message {expected_malformed!r}, got {malformed_msg!r}"


def _error_code_and_msg(fn):
    """Return (code, message) of the call's ClientError; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected this call to fail, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
