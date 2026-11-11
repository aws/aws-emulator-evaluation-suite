"""op-contract-monitor-instances."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-monitor-instances"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """MonitorInstances enables detailed monitoring on a running instance and the state settles
    to 'enabled'; an unknown instance ID is rejected with InvalidParameterValue and its message."""
    ec2 = ctx.client("ec2")
    ami_id = _latest_al2023_ami(ec2)
    instance = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-monitor-")}],
            }
        ],
        SubnetId=ctx.network().subnet_ids[0],
    )["Instances"][0]
    instance_id = instance["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    _wait_for_instance_state(ec2, instance_id, "running", timeout_s=180)

    resp = ec2.monitor_instances(InstanceIds=[instance_id])
    monitoring = resp["InstanceMonitorings"][0]
    assert monitoring["InstanceId"] == instance_id
    assert monitoring["Monitoring"]["State"] in ("pending", "enabled")

    def _monitoring_enabled() -> bool:
        desc = ec2.describe_instances(InstanceIds=[instance_id])
        state = desc["Reservations"][0]["Instances"][0]["Monitoring"]["State"]
        return state == "enabled"

    assert _poll_until(_monitoring_enabled, timeout_s=150, interval_s=5), (
        "instance monitoring never reached 'enabled'"
    )

    unmon = ec2.unmonitor_instances(InstanceIds=[instance_id])
    assert unmon["InstanceMonitorings"][0]["Monitoring"]["State"] in ("pending", "disabling", "disabled")

    # Unlike lifecycle actions such as RebootInstances, MonitorInstances rejects an
    # unrecognized instance ID with InvalidParameterValue, not InvalidInstanceID.NotFound.
    err, message, _ = _client_error(lambda: ec2.monitor_instances(InstanceIds=["i-1234567890abcdef0"]))
    assert err == "InvalidParameterValue", f"expected InvalidParameterValue, got {err}"
    assert message == "Value (i-1234567890abcdef0) for parameter instanceId is invalid. Expected: 'i-...'.", f"unexpected InvalidParameterValue message: {message!r}"


def _latest_al2023_ami(ec2) -> str:
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _wait_for_instance_state(ec2, instance_id, target_state, timeout_s=180.0, interval_s=5.0) -> None:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            desc = ec2.describe_instances(InstanceIds=[instance_id])
        except ClientError as exc:
            # DescribeInstances can briefly report a just-launched instance as not
            # found (eventual consistency); treat that as not ready yet.
            if exc.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
                time.sleep(interval_s)
                continue
            raise
        state = desc["Reservations"][0]["Instances"][0]["State"]["Name"]
        if state == target_state:
            return
        time.sleep(interval_s)
    raise AssertionError(f"instance {instance_id} never reached state {target_state}")


def _poll_until(probe, *, timeout_s=60.0, interval_s=3.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if probe():
            return True
        time.sleep(interval_s)
    return probe()


def _client_error(fn):
    """Return (code, message, http_status) of the ClientError fn() raises; success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message"), exc.response["ResponseMetadata"]["HTTPStatusCode"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
