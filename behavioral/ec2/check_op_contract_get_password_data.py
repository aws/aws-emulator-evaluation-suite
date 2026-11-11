"""op-contract-get-password-data."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags

CHECK = "op-contract-get-password-data"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetPasswordData on a Linux instance returns an empty PasswordData keyed to that instance; a
    digit-mutated instance id fails with InvalidInstanceID.Malformed and its exact message."""
    ec2 = ctx.client("ec2")
    ami_id = _latest_amazon_linux_ami(ctx)

    run_resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[{
            "ResourceType": "instance",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-pwdata-")}],
        }],
        SubnetId=ctx.network().subnet_ids[0],
    )
    instance_id = run_resp["Instances"][0]["InstanceId"]

    def _cleanup():
        ec2.terminate_instances(InstanceIds=[instance_id])
        # Polled rather than the instance_terminated waiter, which fails outright on the
        # "pending" state a just-terminated instance can still report.
        deadline = time.monotonic() + 400.0
        while True:
            state = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]["State"]["Name"]
            if state == "terminated":
                return
            if time.monotonic() >= deadline:
                raise AssertionError(f"instance {instance_id} still {state!r} 400s after TerminateInstances")
            time.sleep(10)
    ctx.on_cleanup(_cleanup)

    # success-path contract: response is keyed to the instance; a Linux instance never
    # gets a generated Windows password, so PasswordData must be the empty string.
    resp = _poll_until(
        lambda: ec2.get_password_data(InstanceId=instance_id),
        lambda r: r["InstanceId"] == instance_id,
        timeout_s=60,
        interval_s=3,
    )
    assert resp["InstanceId"] == instance_id, f"expected InstanceId {instance_id!r}, got: {resp['InstanceId']!r}"
    assert resp["PasswordData"] == "", f"expected empty PasswordData for Linux instance, got: {resp['PasswordData']!r}"

    # error boundary: a syntactically-derived instance ID (all-hex-digits mutated to
    # "f"s) is rejected by GetPasswordData's own ID-format validation before any
    # existence lookup happens, so the error is InvalidInstanceID.Malformed, not NotFound.
    bogus_id = _bogus_id_like(instance_id)
    code, message = _error(lambda: ec2.get_password_data(InstanceId=bogus_id))
    assert code == "InvalidInstanceID.Malformed", f"unexpected error code: {code}"
    assert message == f"The instance ID '{bogus_id}' is malformed", message


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _bogus_id_like(real_id: str) -> str:
    def repl(m):
        return "f" * len(m.group())
    bogus = re.sub(r"[0-9a-f]+$", repl, real_id)
    assert bogus != real_id, "could not derive a distinct bogus id"
    return bogus


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last result: {last!r}")


def _latest_amazon_linux_ami(ctx) -> str:
    ec2 = ctx.client("ec2")
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-2023.*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    if not images:
        raise AssertionError("no Amazon Linux 2023 AMIs found to launch a probe instance")
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
