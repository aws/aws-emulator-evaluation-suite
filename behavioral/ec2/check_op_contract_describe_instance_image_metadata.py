"""op-contract-describeInstanceImageMetadata."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeInstanceImageMetadata"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeInstanceImageMetadata returns the launch AMI for a real instance and
    raises InvalidInstanceID.NotFound for an instance ID that does not exist."""
    ec2 = ctx.client("ec2")
    ami_id = _latest_al2023_ami(ec2)
    instance_id = _launch_probe_instance(ctx, ec2, ami_id)

    def probe():
        # Immediately after RunInstances, DescribeInstanceImageMetadata can
        # transiently raise InvalidInstanceID.NotFound before the instance has
        # fully propagated; treat that as "not ready yet" and keep polling.
        try:
            resp = ec2.describe_instance_image_metadata(InstanceIds=[instance_id])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
                return []
            raise
        return resp.get("InstanceImageMetadata", [])

    # Even once DescribeInstanceImageMetadata acknowledges the instance, the
    # image metadata attributes (e.g. ImageId) can lag slightly behind; poll
    # until the entry is fully populated rather than just present. On real AWS
    # the AMI details are nested under an "ImageMetadata" sub-object rather
    # than a top-level "ImageId" field.
    items = _poll_until(
        probe,
        lambda v: len(v) == 1 and "ImageId" in v[0].get("ImageMetadata", {}),
        timeout_s=90.0,
        interval_s=3.0,
    )
    entry = items[0]
    assert entry["InstanceId"] == instance_id, (
        f"expected instance {instance_id}, got {entry.get('InstanceId')}"
    )
    assert entry["ImageMetadata"]["ImageId"] == ami_id, (
        f"expected AMI {ami_id}, got {entry['ImageMetadata'].get('ImageId')}"
    )

    # A syntactically valid ID of the wrong vintage is the reliable way to get
    # InvalidInstanceID.NotFound: real AWS runs an internal validity check
    # against the *current* (17-hex-character) id format, and both a
    # documentation-placeholder long id and a randomly-flipped-but-real long id
    # fail that check as InvalidInstanceID.Malformed. A legacy short-format id
    # ("i-" + 8 hex chars) is still a
    # recognized valid shape, but this account could never have issued one, so
    # AWS looks it up, finds nothing, and reports the clean not-found code.
    fake_instance_id = "i-deadbeef"
    code, message = _error_of(
        lambda: ec2.describe_instance_image_metadata(InstanceIds=[fake_instance_id])
    )
    assert code == "InvalidInstanceID.NotFound", f"unexpected error code: {code}"
    assert message == f"The instance ID '{fake_instance_id}' does not exist.", message


def _latest_al2023_ami(ec2) -> str:
    resp = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-2023.*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )
    images = sorted(resp["Images"], key=lambda i: i["CreationDate"], reverse=True)
    if not images:

        raise AssertionError("no Amazon Linux 2023 AMI found in this region")
    return images[0]["ImageId"]


def _launch_probe_instance(ctx, ec2, ami_id: str) -> str:
    name = ctx.unique_name("sim2real-behav-ec2-")
    try:
        resp = ec2.run_instances(
            ImageId=ami_id,
            InstanceType="t3.micro",
            MinCount=1,
            MaxCount=1,
            TagSpecifications=[
                {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}
            ],
            SubnetId=ctx.network().subnet_ids[0],
        )
    except ClientError as exc:

        raise AssertionError(f"cannot launch probe instance: {exc.response['Error']['Code']}")
    instance_id = resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    return instance_id


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error_of(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
