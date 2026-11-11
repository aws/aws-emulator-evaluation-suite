"""attach-cluster-node-volume-missing-node-not-found."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "attach-cluster-node-volume-missing-node-not-found"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AttachClusterNodeVolume with a real EBS volume on a nonexistent cluster fails with
    ResourceNotFound and DescribeClusterNode reports the node absent, each with its exact message,
    while a NodeId off the documented pattern fails with ValidationException and its exact message."""
    sm = ctx.client("sagemaker")
    ec2 = ctx.client("ec2")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    fake_cluster_arn = (
        f"arn:aws:sagemaker:{ctx.region}:{account_id}:cluster/{uuid.uuid4().hex[:12]}"
    )
    well_formed_node_id = "i-0123456789abcdef0"

    az = _first_available_az(ec2)
    real_volume_id = ec2.create_volume(
        AvailabilityZone=az,
        Size=1,
        VolumeType="gp3",
        TagSpecifications=[
            {
                "ResourceType": "volume",
                "Tags": [{"Key": "sim2real:managed", "Value": "true"}],
            }
        ],
    )["VolumeId"]
    ctx.on_cleanup(lambda: _delete_volume_with_retry(ec2, real_volume_id))

    code, message = _error(
        lambda: sm.attach_cluster_node_volume(
            ClusterArn=fake_cluster_arn,
            NodeId=well_formed_node_id,
            VolumeId=real_volume_id,
        )
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code}"
    expected = "ClusterNotExistsException: Specified cluster not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # (b) effect absent: the node cannot be described either -- neither the cluster
    # nor the node exist, so nothing could have been attached.
    absent_code, absent_message = _error(
        lambda: sm.describe_cluster_node(
            ClusterName=fake_cluster_arn, NodeId=well_formed_node_id
        )
    )
    assert absent_code == "ResourceNotFound", f"expected ResourceNotFound, got {absent_code}"
    expected_absent = "Specified cluster node not found"
    assert absent_message == expected_absent, f"expected message {expected_absent!r}, got {absent_message!r}"

    # (c) discriminating control: the same call on the same nonexistent cluster and real volume with
    # a NodeId off the `i-[a-f0-9]{8,17}` shape is rejected with ValidationException, not
    # ResourceNotFound.
    malformed_code, malformed_message = _error(
        lambda: sm.attach_cluster_node_volume(
            ClusterArn=fake_cluster_arn,
            NodeId="not-a-real-node-id",
            VolumeId=real_volume_id,
        )
    )
    assert malformed_code == "ValidationException", (
        f"expected ValidationException, got {malformed_code}"
    )
    expected_malformed = (
        "1 validation error detected: Value 'not-a-real-node-id' at 'nodeId' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: i-[a-f0-9]{8}(?:[a-f0-9]{9})?"
    )
    assert malformed_message == expected_malformed, (
        f"expected message {expected_malformed!r}, got {malformed_message!r}"
    )

    # DeleteVolume accepts a volume still `creating` without error but does not remove it, so the
    # volume is waited to `available` before cleanup can delete it.
    _wait_volume_available(ec2, real_volume_id)


def _error(fn):
    """Return (code, message) of the call's ClientError; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to fail, but it SUCCEEDED and returned {result!r}")


def _first_available_az(ec2) -> str:
    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    assert azs, "no available AZs found"
    return azs[0]["ZoneName"]


def _wait_volume_available(ec2, volume_id: str, timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"]
        if state == "available":
            return
        time.sleep(3)
    raise AssertionError(f"volume {volume_id} never reached available, last state={state}")


def _delete_volume_with_retry(ec2, volume_id: str, timeout_s: float = 45.0) -> None:
    """Idempotent delete: NotFound means an earlier attempt already succeeded."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_volume(VolumeId=volume_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidVolume.NotFound":
                return
            if code != "IncorrectState" or time.monotonic() >= deadline:
                raise
            time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
