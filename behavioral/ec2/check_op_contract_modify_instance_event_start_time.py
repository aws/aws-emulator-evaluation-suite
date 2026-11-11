"""op-contract-modify-instance-event-start-time."""
from __future__ import annotations

import datetime

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-modify-instance-event-start-time"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyInstanceEventStartTime rejects a fabricated InstanceId with InvalidInstanceID.Malformed and a
    real instance with an unknown InstanceEventId with InvalidInstanceEventIDNotFound, each with its
    exact message; the two codes differ."""
    ec2 = ctx.client("ec2")
    future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)

    instance_id = _run_instance(ctx, ec2, "t3.micro")
    ctx.on_cleanup(lambda: _terminate(ec2, instance_id))
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    # Any fabricated InstanceId -- however well-shaped -- fails EC2's own internal id checksum and
    # is rejected as Malformed before a lookup is ever attempted; it never reaches
    # InvalidInstanceID.NotFound, even with an all-zeros 17-hex-char suffix.
    bogus_instance_id = "i-" + "0" * 17

    code_bad_instance, msg_bad_instance = _error(
        lambda: ec2.modify_instance_event_start_time(
            InstanceId=bogus_instance_id,
            InstanceEventId="instance-event-0abcdef1234567890",
            NotBefore=future,
        )
    )
    assert code_bad_instance == "InvalidInstanceID.Malformed", (
        f"expected InvalidInstanceID.Malformed, got {code_bad_instance}"
    )
    expected_bad_instance = f"The instance ID '{bogus_instance_id}' is malformed"
    assert msg_bad_instance == expected_bad_instance, f"expected message {expected_bad_instance!r}, got {msg_bad_instance!r}"

    code_bad_event, msg_bad_event = _error(
        lambda: ec2.modify_instance_event_start_time(
            InstanceId=instance_id,
            InstanceEventId="instance-event-0abcdef1234567890",
            NotBefore=future,
        )
    )
    assert code_bad_event == "InvalidInstanceEventIDNotFound", (
        f"expected InvalidInstanceEventIDNotFound, got {code_bad_event}"
    )
    expected_bad_event = "Cannot find event"
    assert msg_bad_event == expected_bad_event, f"expected message {expected_bad_event!r}, got {msg_bad_event!r}"
    assert code_bad_event != code_bad_instance, (
        "expected a distinct rejection for a bogus InstanceId (rejected as malformed "
        "before the InstanceEventId is ever considered) versus a bogus InstanceEventId "
        f"on a real instance: bad-instance={code_bad_instance!r} bad-event={code_bad_event!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses fails loudly instead of as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _latest_al2023_ami(ec2) -> str:
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    if not images:
        raise AssertionError("no amazon-owned al2023 AMIs found in this region")
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _run_instance(ctx, ec2, instance_type: str) -> str:
    ami_id = _latest_al2023_ami(ec2)
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType=instance_type,
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-i-")}],
            }
        ],
        SubnetId=ctx.network().subnet_ids[0],
    )
    return resp["Instances"][0]["InstanceId"]


def _terminate(ec2, instance_id: str) -> None:
    try:
        ec2.terminate_instances(InstanceIds=[instance_id])
        ec2.get_waiter("instance_terminated").wait(
            InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 150}
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
