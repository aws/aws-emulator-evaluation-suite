"""op-contract-modify-instance-credit-specification."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-modify-instance-credit-specification"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyInstanceCreditSpecification sets CpuCredits standard on a t3.micro (read back); a batch
    with an unknown instance id fails with InvalidInstanceID.NotFound naming both ids, and CpuCredits
    stays standard."""
    ec2 = ctx.client("ec2")
    instance_id = _run_instance(ctx, ec2, "t3.micro")
    ctx.on_cleanup(lambda: _terminate(ec2, instance_id))
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    # Establish a real, successful baseline modification first.
    resp = ec2.modify_instance_credit_specification(
        InstanceCreditSpecifications=[{"InstanceId": instance_id, "CpuCredits": "standard"}]
    )
    # The response field names for this operation are "SuccessfulInstanceCreditSpecifications"
    # / "UnsuccessfulInstanceCreditSpecifications" (no "Set" suffix) -- unlike many other older
    # EC2 batch-response shapes (e.g. ModifyHosts' "Successful"/"Unsuccessful"), this operation
    # does not use the "...Set" naming convention.
    successful_ids = [s["InstanceId"] for s in resp["SuccessfulInstanceCreditSpecifications"]]
    assert instance_id in successful_ids, resp
    assert resp["UnsuccessfulInstanceCreditSpecifications"] == [], resp

    described = ec2.describe_instance_credit_specifications(InstanceIds=[instance_id])[
        "InstanceCreditSpecifications"
    ][0]
    assert described["CpuCredits"] == "standard", described

    # Unlike partial-failure batch APIs such as ModifyHosts, ModifyInstanceCreditSpecification
    # rejects the *entire* request with a ClientError if any instance ID is unknown. Its ID-format
    # check rejects a fabricated 17-hex-char id as malformed, so the all-zeros 8-hex-char id shape
    # is used to reach the not-found path.
    bogus_instance_id = "i-" + "0" * 8
    code, message = _client_error(
        lambda: ec2.modify_instance_credit_specification(
            InstanceCreditSpecifications=[
                {"InstanceId": instance_id, "CpuCredits": "unlimited"},
                {"InstanceId": bogus_instance_id, "CpuCredits": "unlimited"},
            ]
        )
    )
    assert code == "InvalidInstanceID.NotFound", f"expected InvalidInstanceID.NotFound, got {code}"
    expected_messages = (
        f"The instance IDs {instance_id}, {bogus_instance_id} do not exist or have been terminated. Change the IDs and try again.",
        f"The instance IDs {bogus_instance_id}, {instance_id} do not exist or have been terminated. Change the IDs and try again.",
    )
    assert message in expected_messages, f"expected one of {expected_messages!r}, got {message!r}"

    # The whole batch was rejected, so the real instance's credit specification must be
    # unaffected -- still "standard" from the earlier, successful call.
    described = ec2.describe_instance_credit_specifications(InstanceIds=[instance_id])[
        "InstanceCreditSpecifications"
    ][0]
    assert described["CpuCredits"] == "standard", described


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
