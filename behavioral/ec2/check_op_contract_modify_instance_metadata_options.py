"""op-contract-modify-instance-metadata-options."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-modify-instance-metadata-options"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyInstanceMetadataOptions applies IMDSv2 settings and rejects an out-of-range hop limit
    without altering the value already applied."""
    ec2 = ctx.client("ec2")
    instance_id = _launch_test_instance(ctx, ec2)

    # positive control: a well-formed write succeeds and converges to applied
    resp = ec2.modify_instance_metadata_options(
        InstanceId=instance_id,
        HttpTokens="required",
        HttpPutResponseHopLimit=3,
        HttpEndpoint="enabled",
    )
    opts = resp["InstanceMetadataOptions"]
    assert opts["HttpTokens"] == "required", f"expected HttpTokens='required' in the write response, got {opts['HttpTokens']!r}"
    assert opts["HttpPutResponseHopLimit"] == 3, (
        f"expected HttpPutResponseHopLimit=3 in the write response, got {opts['HttpPutResponseHopLimit']!r}"
    )
    assert opts["State"] in ("pending", "applied"), (
        f"expected State pending|applied right after the write, got {opts['State']!r}"
    )

    applied = _poll_until(
        lambda: ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0][
            "MetadataOptions"
        ],
        lambda o: o["State"] == "applied"
        and o["HttpTokens"] == "required"
        and o["HttpPutResponseHopLimit"] == 3,
        timeout_s=120,
        interval_s=5,
    )
    assert applied is not None and applied["State"] == "applied", "metadata options never reached 'applied'"

    # break exactly one thing: HttpPutResponseHopLimit is only valid in [1, 64]
    code, message = _error(
        lambda: ec2.modify_instance_metadata_options(InstanceId=instance_id, HttpPutResponseHopLimit=65)
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue for HttpPutResponseHopLimit=65, got {code}"
    assert message == "A value of '65' is not valid for HttpPutResponseHopLimit. Specify a value between 1 and 64 and try again.", message

    # effect absent: an independent read shows the rejected write did not disturb the applied options
    unchanged = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0][
        "MetadataOptions"
    ]
    assert unchanged["HttpPutResponseHopLimit"] == 3, (
        f"a rejected hop-limit write must leave the applied value at 3, got {unchanged['HttpPutResponseHopLimit']!r}"
    )
    assert unchanged["HttpTokens"] == "required", (
        f"a rejected hop-limit write must not disturb HttpTokens, got {unchanged['HttpTokens']!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = probe()
        except ClientError as exc:
            # newly-launched instances can briefly be unreadable via
            # DescribeInstances due to eventual consistency; keep polling.
            if exc.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
                time.sleep(interval_s)
                continue
            raise
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _default_subnet_id(ec2, *, ctx) -> str:
    subnets = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("no network subnet available to launch a test instance")
    return subnets[0]["SubnetId"]


def _latest_al2023_ami(ec2) -> str:
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-2023.*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    if not images:
        raise AssertionError("no Amazon Linux 2023 x86_64 AMI found")
    return sorted(images, key=lambda i: i["CreationDate"])[-1]["ImageId"]


def _launch_test_instance(ctx, ec2, instance_type="t3.micro") -> str:
    ami_id = _latest_al2023_ami(ec2)
    subnet_id = _default_subnet_id(ec2, ctx=ctx)
    name = ctx.unique_name("sim2real-behav-")
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType=instance_type,
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    instance_id = resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    state = _poll_until(
        lambda: ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]["State"][
            "Name"
        ],
        lambda s: s == "running",
        timeout_s=180,
        interval_s=5,
    )
    if state != "running":
        raise AssertionError(
            f"instance {instance_id} never reached running state (last state: {state})"
        )
    return instance_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
