"""run-instances-enclave-options-rejected-on-unsupported-type."""
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


def _error(fn):
    """Return fn()'s (code, message); an unexpected success raises, never a falsy sentinel."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


CHECK = "run-instances-enclave-options-rejected-on-unsupported-type"
GROUP = "instance-response-shape"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RunInstances rejects EnclaveOptions.Enabled True on a t3.micro with InvalidParameterValue
    and creates nothing, while the same type with Enabled False launches normally."""
    ec2 = ctx.client("ec2")
    ami = _test_ami_id(ec2)
    subnet_id = ctx.network().subnet_ids[0]
    attempt_tag = ctx.unique_name("sim2real-behav-enclave-")

    code, message = _error(lambda: ec2.run_instances(
        ImageId=ami, InstanceType="t3.micro", MinCount=1, MaxCount=1,
        SubnetId=subnet_id,
        EnclaveOptions={"Enabled": True},
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "sim2real", "Value": attempt_tag}]}],
    ))
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    expected_message = (
        'You cannot enable Nitro Enclaves for "t3.micro" instance types. '
        "Specify a supported instance type and try again."
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # effect absent: the refused call minted no instance under its own tag.
    leaked = ec2.describe_instances(
        Filters=[{"Name": "tag:sim2real", "Values": [attempt_tag]}]
    )["Reservations"]
    assert leaked == [], f"expected no instance tagged {attempt_tag!r}, found {leaked!r}"

    # positive control: the legal neighbor (Enabled False, same type) launches normally.
    instance_id = ec2.run_instances(
        ImageId=ami, InstanceType="t3.micro", MinCount=1, MaxCount=1,
        SubnetId=subnet_id,
        EnclaveOptions={"Enabled": False},
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    _wait_instance_state(ec2, instance_id, "running")
    inst = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    assert inst["EnclaveOptions"].get("Enabled") is False, (
        f"expected the control launch's EnclaveOptions.Enabled False, got "
        f"{inst['EnclaveOptions'].get('Enabled')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
