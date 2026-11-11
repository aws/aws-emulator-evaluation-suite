"""create-tags-and-filter-describe-instances."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError


from behavioral_harness import tags


def _test_ami_id(ec2):
    """Return an x86_64 HVM EBS ImageId usable for RunInstances tests."""
    strict = [
        {"Name": "state", "Values": ["available"]},
        {"Name": "architecture", "Values": ["x86_64"]},
        {"Name": "virtualization-type", "Values": ["hvm"]},
        {"Name": "root-device-type", "Values": ["ebs"]},
    ]
    attempts = [
        {"Owners": ["amazon"], "Filters": strict + [{"Name": "name", "Values": ["al2023-ami-2023*-x86_64"]}]},
        {"Owners": ["amazon"], "Filters": strict + [{"Name": "name", "Values": ["amzn2-ami-hvm-*-x86_64-gp2"]}]},
        {"Owners": ["amazon"], "Filters": strict},
    ]
    for kw in attempts:
        try:
            images = ec2.describe_images(**kw).get("Images", [])
        except Exception:
            continue
        if not images:
            continue
        images.sort(key=lambda i: i.get("CreationDate", ""), reverse=True)
        return images[0]["ImageId"]
    raise AssertionError("could not discover a usable test AMI")


def _wait_instance_state(ec2, instance_id, state, timeout_s=180):
    """Poll DescribeInstances until the instance reaches *state* (swallows the
    eventually-consistent InvalidInstanceID.NotFound window right after launch)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = ec2.describe_instances(InstanceIds=[instance_id])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidInstanceID.NotFound":
                last = "__not_yet_visible__"
                time.sleep(3)
                continue
            raise
        reservations = resp.get("Reservations", [])
        if not reservations or not reservations[0].get("Instances"):
            last = "__not_yet_visible__"
        else:
            last = reservations[0]["Instances"][0]["State"]["Name"]
        if last == state:
            return last
        time.sleep(3)
    raise AssertionError(
        f"instance {instance_id} did not reach {state!r} within {timeout_s}s (last {last!r})"
    )


CHECK = "create-tags-and-filter-describe-instances"
GROUP = 'tagging'
SERVICES = ['ec2']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTags propagates to the resource, and DescribeInstances tag-filters return exactly the tagged resource."""
    ec2 = ctx.client("ec2")
    ami = _test_ami_id(ec2)
    instance_id = ec2.run_instances(
        ImageId=ami, InstanceType="t3.micro", MinCount=1, MaxCount=1,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
        SubnetId=ctx.network().subnet_ids[0],
    )["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    _wait_instance_state(ec2, instance_id, "running")
    marker = ctx.unique_name("sim2real-behav-marker-")

    ec2.create_tags(Resources=[instance_id], Tags=[{"Key": "behavioral-marker", "Value": marker}])

    described = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    tag_map = {t["Key"]: t["Value"] for t in described.get("Tags", [])}
    assert tag_map.get("behavioral-marker") == marker

    filtered = ec2.describe_instances(
        Filters=[{"Name": "tag:behavioral-marker", "Values": [marker]}]
    )
    found_ids = {
        i["InstanceId"]
        for r in filtered["Reservations"]
        for i in r["Instances"]
    }
    assert found_ids == {instance_id}, f"expected filter to isolate {instance_id}, got {found_ids}"

    # negative control: a filter for a marker that was never set must exclude this instance,
    # proving the tag filter discriminates on value rather than being ignored (which would
    # otherwise pass trivially in an account with no other running instances).
    decoy = ctx.unique_name("sim2real-behav-marker-decoy-")
    excluded = ec2.describe_instances(
        Filters=[{"Name": "tag:behavioral-marker", "Values": [decoy]}]
    )
    excluded_ids = {
        i["InstanceId"]
        for r in excluded["Reservations"]
        for i in r["Instances"]
    }
    assert instance_id not in excluded_ids, (
        f"filter for unrelated marker {decoy!r} must not return {instance_id}, got {excluded_ids}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
