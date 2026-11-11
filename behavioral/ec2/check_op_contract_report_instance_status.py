"""op-contract-report-instance-status."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-report-instance-status"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ReportInstanceStatus accepts a status report for a real, running
    instance (success contract), and rejects a malformed instance ID."""
    ec2 = ctx.client("ec2")

    ami_id = _latest_al2023_ami(ec2)
    instance = ec2.run_instances(
        ImageId=ami_id, InstanceType="t3.micro", MinCount=1, MaxCount=1,
        TagSpecifications=_tags("instance", ctx.unique_name("sim2real-ris-")),
        SubnetId=ctx.network().subnet_ids[0],
    )["Instances"][0]
    instance_id = instance["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    _poll_until(lambda: ec2.describe_instances(InstanceIds=[instance_id])
                ["Reservations"][0]["Instances"][0]["State"]["Name"],
                lambda s: s == "running", timeout_s=180, interval_s=5, ignore_not_found=True)

    resp = ec2.report_instance_status(
        Instances=[instance_id], Status="impaired",
        ReasonCodes=["instance-stuck-in-state"], Description="sim2real behavioral check",
    )
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200

    # ReportInstanceStatus is a lightweight, fire-and-forget health signal: on
    # real AWS it does not appear to validate that a well-formed instance ID
    # actually corresponds to an existing instance (it accepts the report
    # regardless), so a well-formed-but-unassigned instance ID isn't a
    # reliable rejection trigger. A malformed instance ID, however, is always
    # rejected at the request-parsing stage.
    code, message = _client_error(lambda: ec2.report_instance_status(
        Instances=["not-an-instance-id"], Status="impaired",
        ReasonCodes=["instance-stuck-in-state"],
    ))
    assert code == "InvalidInstanceID.Malformed", f"expected InvalidInstanceID.Malformed, got {code}"
    expected_message = "The instance ID 'not-an-instance-id' is malformed"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _tags(resource_type: str, name: str) -> list[dict]:
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}]


def _client_error(fn):
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0, ignore_not_found=False):
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = probe()
        except ClientError as exc:
            if ignore_not_found and exc.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
                time.sleep(interval_s)
                continue
            raise
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _latest_al2023_ami(ec2) -> str:
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    if not images:
        raise AssertionError("no al2023 AMI found in this region")
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
