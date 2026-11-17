"""deploy-ec2-network-interface-attachment-delete-on-termination-round-trip-and-delete."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ec2-network-interface-attachment-delete-on-termination-round-trip-and-delete"
GROUP = "deploy-cfn-resource-existence"
SERVICES = ["cloudformation", "ec2"]

INSTANCE_TYPE = "t3.micro"
AMI_PARAMETER = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
VPC_BLOCK = "10.85.0.0/16"
SUBNET_BLOCK = "10.85.0.0/24"
_ENI_NOT_FOUND = (
    "InvalidNetworkInterfaceID.NotFound",
    "The networkInterface ID '{}' does not exist",
)


def _template() -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "Az": {"Type": "String"},
            "Ami": {
                "Type": "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
                "Default": AMI_PARAMETER,
            },
        },
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": VPC_BLOCK}},
            "Subnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "Vpc"},
                    "CidrBlock": SUBNET_BLOCK,
                    "AvailabilityZone": {"Ref": "Az"},
                },
            },
            "Instance": {
                "Type": "AWS::EC2::Instance",
                "Properties": {
                    "ImageId": {"Ref": "Ami"},
                    "InstanceType": INSTANCE_TYPE,
                    "SubnetId": {"Ref": "Subnet"},
                },
            },
            "Eni": {
                "Type": "AWS::EC2::NetworkInterface",
                "Properties": {
                    "SubnetId": {"Ref": "Subnet"},
                },
            },
            "NicAttach": {
                "Type": "AWS::EC2::NetworkInterfaceAttachment",
                "Properties": {
                    "InstanceId": {"Ref": "Instance"},
                    "NetworkInterfaceId": {"Ref": "Eni"},
                    "DeviceIndex": "1",
                    "DeleteOnTermination": False,
                },
            },
        },
        "Outputs": {
            "InstanceId": {"Value": {"Fn::GetAtt": ["Instance", "InstanceId"]}},
            "EniId": {"Value": {"Ref": "Eni"}},
        },
    }


_CREATE_TERMINAL = frozenset(
    {
        "CREATE_COMPLETE",
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "DELETE_COMPLETE",
        "DELETE_FAILED",
    }
)
_DELETE_TERMINAL = frozenset({"DELETE_COMPLETE", "DELETE_FAILED"})


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _stack(cfn, stack_id: str) -> dict:
    """The stack read by StackId; the exact not-found pair reads as DELETE_COMPLETE."""
    try:
        return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    except ClientError as exc:
        err = exc.response["Error"]
        if (err.get("Code"), err.get("Message")) == (
            "ValidationError",
            f"Stack with id {stack_id} does not exist",
        ):
            return {"StackId": stack_id, "StackStatus": "DELETE_COMPLETE"}
        raise


def _wait_stack(ctx, cfn, stack_id: str, terminal, timeout_s: float) -> dict:
    return _poll_until(
        ctx,
        lambda: _stack(cfn, stack_id),
        lambda s: s["StackStatus"] in terminal,
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"stack {stack_id} reaches one of {sorted(terminal)}",
    )


def _delete_stack(ctx, cfn, stack_id: str, timeout_s: float = 900.0) -> None:
    """Delete the stack whatever state it is in, and raise unless it reaches DELETE_COMPLETE."""
    cfn.delete_stack(StackName=stack_id)
    final = _wait_stack(ctx, cfn, stack_id, _DELETE_TERMINAL, timeout_s)
    if final["StackStatus"] != "DELETE_COMPLETE":
        raise RuntimeError(
            f"stack {stack_id} delete ended {final['StackStatus']!r}: "
            f"{final.get('StackStatusReason')!r}"
        )


def _usable_az(ec2) -> str:
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [INSTANCE_TYPE]}],
        )["InstanceTypeOfferings"]
    }
    usable = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
        if z["ZoneName"] in offered
    )
    assert usable, f"no available AZ offers {INSTANCE_TYPE!r}; offerings were {sorted(offered)!r}"
    return usable[0]


def _expect_error(fn, code: str, message: str) -> None:
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code!r} but the call succeeded: {result!r}")


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN NetworkInterfaceAttachment declaring DeleteOnTermination false reads back through
    DescribeNetworkInterfaces with that exact value, and the interface outlives the instance it
    was attached to, detached and 'available', once that instance alone is terminated."""
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    az = _usable_az(ec2)

    name = ctx.unique_name("sim2real-xsvc-ec2nicdot-")
    stack_id = cfn.create_stack(
        StackName=name,
        TemplateBody=json.dumps(_template()),
        Parameters=[{"ParameterKey": "Az", "ParameterValue": az}],
        Tags=[{"Key": "sim2real", "Value": name}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(ctx, cfn, stack_id))

    stack = _wait_stack(ctx, cfn, stack_id, _CREATE_TERMINAL, 600.0)
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), "
        f"expected 'CREATE_COMPLETE'"
    )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    instance_id, eni_id = outputs["InstanceId"], outputs["EniId"]

    eni = ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id])["NetworkInterfaces"][0]
    attachment = eni["Attachment"]
    assert attachment["DeleteOnTermination"] is False, (
        f"EC2 reports Attachment.DeleteOnTermination {attachment['DeleteOnTermination']!r}, "
        f"expected the template's False"
    )
    assert attachment["InstanceId"] == instance_id, (
        f"EC2 reports the interface attached to {attachment['InstanceId']!r}, expected {instance_id!r}"
    )

    # Terminate only the instance (not the stack) to prove the property's effect: with
    # DeleteOnTermination false, the interface must outlive the instance that held it.
    ec2.terminate_instances(InstanceIds=[instance_id])
    _poll_until(
        ctx,
        lambda: ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][
            0
        ]["State"]["Name"],
        lambda state: state == "terminated",
        timeout_s=600.0,
        interval_s=5.0,
        description=f"instance {instance_id} terminated",
    )

    # Detaching follows termination asynchronously: poll until the interface reads 'available'.
    survived = _poll_until(
        ctx,
        lambda: ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id])["NetworkInterfaces"][
            0
        ],
        lambda e: e["Status"] == "available",
        timeout_s=300.0,
        interval_s=5.0,
        description=f"interface {eni_id} 'available' after the instance terminated",
    )
    assert "Attachment" not in survived, (
        f"expected no attachment on the surviving interface, EC2 reports {survived['Attachment']!r}"
    )

    _delete_stack(ctx, cfn, stack_id)
    gone_code, gone_message = _ENI_NOT_FOUND
    _expect_error(
        lambda: ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id]),
        gone_code,
        gone_message.format(eni_id),
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
