"""create-mac-sip-modification-task-rejected-unknown-instance."""
from __future__ import annotations

import secrets

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-mac-sip-modification-task-rejected-unknown-instance"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateMacSystemIntegrityProtectionModificationTask refuses the all-zero and a random unallocated instance id
    with InvalidInstanceID.Malformed and its exact message, while a running non-Mac instance gets a different
    code.
    """
    ec2 = ctx.client("ec2")

    # MacSystemIntegrityProtectionStatus is a title-cased enum ("Enabled" / "Disabled"); a
    # lowercase value fails botocore's client-side parameter validation before the request
    # ever reaches EC2, which would mask the InstanceId boundary this check exercises.
    code_all_zero, message_all_zero = _error(
        lambda: ec2.create_mac_system_integrity_protection_modification_task(
            InstanceId="i-00000000000000000",
            MacSystemIntegrityProtectionStatus="Disabled",
        )
    )
    assert code_all_zero == "InvalidInstanceID.Malformed", (
        f"expected InvalidInstanceID.Malformed for the all-zero placeholder, got {code_all_zero!r}"
    )
    assert message_all_zero == "The instance ID 'i-00000000000000000' is malformed", message_all_zero

    # A non-zero leading digit puts the 17-digit id outside the range EC2 issues.
    random_id = "i-f" + secrets.token_hex(8)
    code_random, message_random = _error(
        lambda: ec2.create_mac_system_integrity_protection_modification_task(
            InstanceId=random_id,
            MacSystemIntegrityProtectionStatus="Disabled",
        )
    )
    assert code_random == "InvalidInstanceID.Malformed", (
        f"expected InvalidInstanceID.Malformed for a well-formed unallocated id, got {code_random!r}"
    )
    assert message_random == f"The instance ID '{random_id}' is malformed", message_random

    real_instance_id = _launch_probe_instance(ctx)
    code_real, _ = _error(
        lambda: ec2.create_mac_system_integrity_protection_modification_task(
            InstanceId=real_instance_id,
            MacSystemIntegrityProtectionStatus="Disabled",
        )
    )
    assert code_real != "InvalidInstanceID.Malformed", (
        "a real, existing (non-Mac) instance must not be rejected with the same "
        f"Malformed code as an unallocated placeholder id, got {code_real!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _default_vpc_subnet(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    return subnets[0]["SubnetId"]


def _latest_al2023_ami(ec2):
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _launch_probe_instance(ctx):
    ec2 = ctx.client("ec2")
    subnet_id = _default_vpc_subnet(ctx)
    ami_id = _latest_al2023_ami(ec2)
    name = ctx.unique_name("sim2real-mac-sip-probe-")
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "sim2real", "Value": name}]}],
    )
    instance_id = resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    return instance_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
