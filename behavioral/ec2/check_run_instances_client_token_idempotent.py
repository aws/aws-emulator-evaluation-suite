"""run-instances-client-token-idempotent."""
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
        images = ec2.describe_images(**kw).get("Images", [])
        if not images:
            continue
        images.sort(key=lambda i: i.get("CreationDate", ""), reverse=True)
        return images[0]["ImageId"]
    raise AssertionError("could not discover a usable test AMI")


def _wait_instance_state(ec2, instance_id, state, timeout_s=180):
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

CHECK = "run-instances-client-token-idempotent"
GROUP = 'concurrency'
SERVICES = ['ec2']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Repeated RunInstances calls sharing a ClientToken must create exactly one instance."""
    ec2 = ctx.client("ec2")
    token = ctx.unique_name("sim2real-behav-token-")
    image_id = _test_ami_id(ec2)

    def launch():
        resp = ec2.run_instances(
            ImageId=image_id,
            InstanceType="t3.micro",
            MinCount=1,
            MaxCount=1,
            ClientToken=token,
            TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
            SubnetId=ctx.network().subnet_ids[0],
        )
        return resp["Instances"][0]["InstanceId"]

    # The documented idempotency contract is about *retries* of an identical
    # request, so replay the same request sequentially and require the service
    # to return the same instance every time rather than launching more.
    first_id = launch()
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[first_id]))

    replay_ids = {launch() for _ in range(3)}
    assert replay_ids == {first_id}, (
        f"ClientToken retries must return the single original instance {first_id}, got {replay_ids}"
    )

    _wait_instance_state(ec2, first_id, "running")

    # Authoritative confirmation: filtering by the client token must match exactly
    # one non-terminated instance, proving no duplicate launch occurred.
    resp = ec2.describe_instances(Filters=[{"Name": "client-token", "Values": [token]}])
    matched = {
        i["InstanceId"]
        for r in resp["Reservations"]
        for i in r["Instances"]
        if i["State"]["Name"] != "terminated"
    }
    assert matched == {first_id}, f"expected exactly one instance for token, got {matched}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
