"""create-delegate-mac-volume-ownership-task-invalid-instance-rejected."""
from __future__ import annotations

import base64
import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-delegate-mac-volume-ownership-task-invalid-instance-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDelegateMacVolumeOwnershipTask refuses an unallocated instance id with InvalidInstanceID.Malformed and a
    running non-Mac instance with InvalidInstanceType, each with its exact message: the answer depends on the id.
    """
    ec2 = ctx.client("ec2")
    if not hasattr(ec2, "create_delegate_mac_volume_ownership_task"):
        raise AssertionError("installed botocore does not support CreateDelegateMacVolumeOwnershipTask")

    # MacCredentials must be valid Base64 or request validation refuses it before the instance lookup,
    # so a placeholder payload is Base64-encoded.
    credentials = base64.b64encode(
        json.dumps(
            {
                "internalDiskPassword": "",
                "rootVolumeUsername": "ec2-user",
                "rootVolumepassword": "placeholder-password-1",
            }
        ).encode("utf-8")
    ).decode("ascii")

    # Positive control: a real, running, non-Mac instance is a wholly different
    # rejection reason than a nonexistent id -- proving the boundary discriminates
    # on the id it is given rather than refusing the operation outright.
    image_id = _latest_amazon_linux_ami(ec2)
    instance_name = ctx.unique_name("sim2real-mvot-")
    reservation = ec2.run_instances(
        ImageId=image_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": instance_name}]}
        ],
        SubnetId=ctx.network().subnet_ids[0],
    )
    real_instance_id = reservation["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[real_instance_id]))
    ec2.get_waiter("instance_running").wait(
        InstanceIds=[real_instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 100}
    )

    real_code, real_message = _error_detail(
        lambda: ec2.create_delegate_mac_volume_ownership_task(
            InstanceId=real_instance_id, MacCredentials=credentials
        )
    )
    assert real_code == "InvalidInstanceType", (
        f"expected InvalidInstanceType for a real but non-Mac instance, got {real_code!r} ({real_message})"
    )
    assert real_message == "The instance type is not supported for this operation", f"unexpected error message {real_message!r}"
    assert real_code != "InvalidInstanceID.Malformed", (
        f"real, existing instance {real_instance_id!r} got the same code as a nonexistent id "
        f"({real_code!r}) -- the boundary is not discriminating on id validity"
    )

    bogus_instance_id = "i-0123456789abcdef0"
    code, message = _error_detail(
        lambda: ec2.create_delegate_mac_volume_ownership_task(
            InstanceId=bogus_instance_id, MacCredentials=credentials
        )
    )
    assert code == "InvalidInstanceID.Malformed", (
        f"expected InvalidInstanceID.Malformed, got {code!r} ({message})"
    )
    assert message == f"The instance ID '{bogus_instance_id}' is malformed", f"unexpected error message {message!r}"


def _latest_amazon_linux_ami(ec2):
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    if not images:
        raise AssertionError("no Amazon Linux 2023 AMI found to launch from")
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _error_detail(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
