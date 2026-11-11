"""enable-application-status-check-suppression-contract."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "enable-application-status-check-suppression-contract"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """EnableApplicationStatusCheckSuppression rejects a batch holding a malformed instance id with
    InvalidInstanceID.Malformed and its exact message, and for a running instance returns it in
    SuccessfulResults with SuppressAt and ResumeAt; Disable succeeds for it too.
    """
    ec2 = ctx.client("ec2")

    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not default_vpcs:
        raise AssertionError("no shared network VPC available to launch a test instance")
    default_vpc_id = default_vpcs[0]["VpcId"]

    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [default_vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("no subnet available in the shared network")
    subnet_id = subnets[0]["SubnetId"]

    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    if not images:
        raise AssertionError("no suitable AMI found to launch a test instance")
    images.sort(key=lambda i: i.get("CreationDate", ""), reverse=True)
    ami_id = images[0]["ImageId"]

    run_resp = ec2.run_instances(
        ImageId=ami_id, InstanceType="t3.micro", MinCount=1, MaxCount=1, SubnetId=subnet_id,
        TagSpecifications=[_tag_spec("instance", ctx.unique_name("sim2real-appsc-"))],
    )
    instance_id = run_resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))

    def _instance_state():
        # Right after RunInstances, DescribeInstances can answer InvalidInstanceID.NotFound for
        # the new instance; that reads as "still pending".
        from botocore.exceptions import ClientError

        try:
            return ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]["State"]["Name"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidInstanceID.NotFound":
                return "pending"
            raise

    state = _poll_until(
        _instance_state,
        lambda s: s != "pending",
        timeout_s=120.0, interval_s=5.0,
        description="instance leaving pending state",
    )
    assert state == "running", f"expected the instance to reach running, got {state!r}"

    # NEGATIVE (checked first, before any suppression exists): batching a real instance ID
    # together with a well-formed but nonexistent one does not partially succeed -- real AWS
    # rejects the whole call with InvalidInstanceID.Malformed and applies no suppression at all.
    bogus_instance_id = "i-0123456789abcdef0"
    code, message = _error(lambda: ec2.enable_application_status_check_suppression(
        InstanceIds=[instance_id, bogus_instance_id], DurationSeconds=3600
    ))
    assert code == "InvalidInstanceID.Malformed", f"unexpected error code for mixed batch: {code}"
    assert message == f"The instance ID '{bogus_instance_id}' is malformed", message

    # POSITIVE: suppressing only the real instance lands in SuccessfulResults with SuppressAt and
    # ResumeAt. A new instance's status checks stay "initializing" for a few minutes, so the
    # suppression call itself is retried until the instance appears in SuccessfulResults.
    def _try_enable():
        resp = ec2.enable_application_status_check_suppression(InstanceIds=[instance_id], DurationSeconds=3600)
        successful = {item["InstanceId"]: item for item in resp.get("SuccessfulResults", [])}
        return resp, instance_id in successful

    resp, _ok = _poll_until(
        _try_enable, lambda r: r[1], timeout_s=600.0, interval_s=20.0,
        description="instance appearing in SuccessfulResults for EnableApplicationStatusCheckSuppression",
    )

    successful = {item["InstanceId"]: item for item in resp.get("SuccessfulResults", [])}
    assert instance_id in successful, f"expected {instance_id} in SuccessfulResults, got {resp}"
    assert "SuppressAt" in successful[instance_id] and "ResumeAt" in successful[instance_id]

    # TERMINAL: no Describe/Get operation reports per-instance suppression, so the independent
    # read is DisableApplicationStatusCheckSuppression, whose SuccessfulResults lists only an
    # instance that was suppressed (UnsuccessfulResults with a Reason otherwise).
    disable_resp = ec2.disable_application_status_check_suppression(InstanceIds=[instance_id])
    disable_successful = {item["InstanceId"]: item for item in disable_resp.get("SuccessfulResults", [])}
    assert instance_id in disable_successful, (
        f"expected {instance_id} in DisableApplicationStatusCheckSuppression's SuccessfulResults "
        f"(confirming the earlier suppression was really active), got {disable_resp}"
    )


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
