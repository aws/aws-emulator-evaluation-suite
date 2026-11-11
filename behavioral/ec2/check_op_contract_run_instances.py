"""op-contract-run-instances."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-run-instances"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RunInstances launches an Amazon-owned AMI that reaches "running" with InstanceType t3.micro and the
    requested Name tag; a malformed AMI id fails with InvalidAMIID.Malformed and its exact message."""
    ec2 = ctx.client("ec2")

    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
            {"Name": "root-device-type", "Values": ["ebs"]},
        ],
    )["Images"]
    if not images:
        images = ec2.describe_images(
            Owners=["amazon"],
            Filters=[
                {"Name": "name", "Values": ["amzn2-ami-hvm-*-x86_64-gp2"]},
                {"Name": "state", "Values": ["available"]},
            ],
        )["Images"]
    assert images, "no suitable Amazon-owned AMI found to launch"
    ami_id = sorted(images, key=lambda i: i["CreationDate"], reverse=True)[0]["ImageId"]

    name_tag = ctx.unique_name("sim2real-run-instances-")
    run_resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name_tag}]}
        ],
        SubnetId=ctx.network().subnet_ids[0],
    )
    instance_id = run_resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))

    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    desc = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    assert desc["State"]["Name"] == "running", f"unexpected state: {desc['State']}"
    assert desc["InstanceType"] == "t3.micro", f"unexpected InstanceType: {desc['InstanceType']}"
    tag_map = {t["Key"]: t["Value"] for t in desc.get("Tags", [])}
    assert tag_map.get("Name") == name_tag, f"Name tag missing/wrong: {tag_map}"

    # The "...1234567890abcdef0" long-format id is the placeholder AWS's own docs/SDK
    # examples use for a syntactically valid resource id, but on real AWS RunInstances
    # rejects it before ever reaching the existence check: it fails RunInstances' own AMI
    # id format validator, producing InvalidAMIID.Malformed rather than InvalidAMIID.NotFound.
    try:
        malformed_resp = ec2.run_instances(
            ImageId="ami-1234567890abcdef0",
            InstanceType="t3.micro",
            MinCount=1,
            MaxCount=1,
            SubnetId=ctx.network().subnet_ids[0],
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message", "")
    else:
        leaked_ids = [i["InstanceId"] for i in malformed_resp["Instances"]]
        ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=leaked_ids))
        raise AssertionError(
            "expected RunInstances to reject ami-1234567890abcdef0 with "
            f"InvalidAMIID.Malformed, but it SUCCEEDED and launched {leaked_ids!r}"
        )
    assert code == "InvalidAMIID.Malformed", f"unexpected error code: {code}"
    expected = 'Invalid id: "ami-1234567890abcdef0" (expecting "ami-...")'
    assert message == expected, f"unexpected message: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
