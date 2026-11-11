"""op-contract-stop-instances."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-stop-instances"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StopInstances transitions a running instance to stopped; bogus instance -> NotFound."""
    ec2 = ctx.client("ec2")
    instance_id = _launch_instance(ctx)

    # success path
    resp = ec2.stop_instances(InstanceIds=[instance_id])
    change = resp["StoppingInstances"][0]
    assert change["PreviousState"]["Name"] == "running", (
        f"expected PreviousState running, got {change['PreviousState']['Name']!r}"
    )
    assert change["CurrentState"]["Name"] in ("stopping", "stopped"), (
        f"expected CurrentState stopping/stopped, got {change['CurrentState']['Name']!r}"
    )
    _wait_instance_state(ctx, instance_id, {"stopped"})

    # error boundary: nonexistent instance id, same shape as a real one. Real EC2's
    # instance-id shape check is not a plain length/charset test: rotating a single hex
    # digit of a real id sometimes still trips InvalidInstanceID.Malformed rather than
    # NotFound, and which digit positions are safe varies per id. So probe digit positions until real
    # AWS itself confirms one is shape-valid-but-absent, rather than assuming any single
    # rotation is safe.
    prefix, digits = instance_id[:2], instance_id[2:]
    bogus_code = bogus_message = candidate = None
    for i in range(len(digits)):
        candidate = prefix + digits[:i] + format((int(digits[i], 16) + 1) % 16, "x") + digits[i + 1:]
        bogus_code, bogus_message = _error_code(lambda c=candidate: ec2.stop_instances(InstanceIds=[c]))
        if bogus_code == "InvalidInstanceID.NotFound":
            break
        assert bogus_code == "InvalidInstanceID.Malformed", (
            f"expected Malformed or NotFound for same-shape mutated id, got {bogus_code}"
        )
        assert bogus_message == f"The instance ID '{candidate}' is malformed", bogus_message
    assert bogus_code == "InvalidInstanceID.NotFound", (
        f"no single-digit rotation of {instance_id!r} was accepted as shape-valid-but-absent "
        f"(all {len(digits)} rotations returned Malformed)"
    )
    assert bogus_message == f"The instance ID '{candidate}' does not exist", bogus_message


def _error_code(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
    emulator accepting a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _latest_al2023_ami(ctx):
    ec2 = ctx.client("ec2")
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    assert images, "no al2023 AMIs found"
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _wait_instance_state(ctx, instance_id, states, timeout_s=300.0):
    ec2 = ctx.client("ec2")

    def probe():
        from botocore.exceptions import ClientError

        try:
            resp = ec2.describe_instances(InstanceIds=[instance_id])
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
                # transient eventual-consistency gap right after a state change;
                # keep polling instead of failing outright.
                return None
            raise
        return resp["Reservations"][0]["Instances"][0]["State"]["Name"]

    return _poll_until(probe, lambda s: s in states, timeout_s=timeout_s)


def _launch_instance(ctx, instance_type="t3.micro", **kwargs):
    ec2 = ctx.client("ec2")
    ami = _latest_al2023_ami(ctx)
    resp = ec2.run_instances(
        ImageId=ami,
        InstanceType=instance_type,
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-inst-")}],
            }
        ],
        **kwargs,
        SubnetId=ctx.network().subnet_ids[0],
    )
    instance_id = resp["Instances"][0]["InstanceId"]

    def _cleanup():
        try:
            ec2.terminate_instances(InstanceIds=[instance_id])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
                raise

    ctx.on_cleanup(_cleanup)
    _wait_instance_state(ctx, instance_id, {"running"})
    return instance_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
