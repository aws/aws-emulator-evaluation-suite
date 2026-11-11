"""op-contract-associateTrunkInterface."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-associateTrunkInterface"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateTrunkInterface with DryRun answers DryRunOperation; the real call on an eligible,
    attached trunk ENI is refused with OperationNotPermitted, because ENI trunking is reserved for
    AWS-managed integrations, and DescribeTrunkInterfaceAssociations is refused the same way."""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    vpc = ec2.create_vpc(CidrBlock="10.197.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _cleanup(lambda: ec2.delete_vpc(VpcId=vpc)))
    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.197.1.0/24", AvailabilityZone=az)["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _cleanup(lambda: ec2.delete_subnet(SubnetId=subnet)))

    trunk_eni = ec2.create_network_interface(
        SubnetId=subnet,
        InterfaceType="trunk",
        TagSpecifications=[
            {"ResourceType": "network-interface", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-trunk-")}]}
        ],
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: _cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=trunk_eni)))

    branch_eni = ec2.create_network_interface(
        SubnetId=subnet,
        TagSpecifications=[
            {"ResourceType": "network-interface", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-branch-")}]}
        ],
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: _cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=branch_eni)))

    # AssociateTrunkInterface is rejected with OperationNotPermitted for a trunk ENI that isn't
    # attached to anything -- the hypervisor needs a running (Nitro/ENA-trunking-capable) instance
    # to own the trunk before it can fan branch traffic out over it. Launch one and attach the
    # trunk ENI as a secondary interface before exercising the DryRun/success paths.
    ami = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64")[
        "Parameter"
    ]["Value"]
    # ENI trunking (branch/trunk interfaces) is only supported on Nitro-based, non-burstable
    # instance families; t3 (burstable, and not on the trunking-capable list at all) rejects
    # AttachNetworkInterface for a trunk-type ENI with UnsupportedOperation. c5 is on AWS's
    # documented trunking-capable instance list.
    instance = ec2.run_instances(
        ImageId=ami,
        InstanceType="c5.large",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-trunk-host-")}]}
        ],
    )["Instances"][0]["InstanceId"]

    def cleanup_instance():
        _cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance]))
        _cleanup(lambda: ec2.get_waiter("instance_terminated").wait(InstanceIds=[instance], WaiterConfig={"Delay": 2, "MaxAttempts": 300}))

    ctx.on_cleanup(cleanup_instance)
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    attachment_id = ec2.attach_network_interface(NetworkInterfaceId=trunk_eni, InstanceId=instance, DeviceIndex=1)[
        "AttachmentId"
    ]

    def cleanup_trunk_attachment():
        _cleanup(lambda: ec2.detach_network_interface(AttachmentId=attachment_id, Force=True))
        _cleanup(
            lambda: _poll_until(
                lambda: ec2.describe_network_interfaces(NetworkInterfaceIds=[trunk_eni])["NetworkInterfaces"][0][
                    "Status"
                ],
                lambda s: s == "available",
                timeout_s=60,
                interval_s=3,
            )
        )

    ctx.on_cleanup(cleanup_trunk_attachment)
    _poll_until(
        lambda: ec2.describe_network_interfaces(NetworkInterfaceIds=[trunk_eni])["NetworkInterfaces"][0],
        lambda ni: ni.get("Attachment", {}).get("Status") == "attached",
        timeout_s=60,
        interval_s=3,
    )

    # error boundary: DryRun must short-circuit with DryRunOperation before any mutation
    code, code_message = _error_code(
        lambda: ec2.associate_trunk_interface(
            BranchInterfaceId=branch_eni, TrunkInterfaceId=trunk_eni, VlanId=7, DryRun=True
        )
    )
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    expected_code_message = "Request would have succeeded, but DryRun flag is set."
    assert code_message == expected_code_message, f"expected message {expected_code_message!r}, got {code_message!r}"

    # withdrawal boundary: the non-DryRun call is rejected with the specific OperationNotPermitted
    # code -- never a generic ValidationError, never a silent success -- for this same, now
    # legitimately eligible (attached, running-instance-owned) trunk ENI. This is the observable,
    # testable contract: ENI trunking's real association path is not something any customer
    # principal can complete, regardless of permissions or setup correctness.
    code, code_message = _error_code(
        lambda: ec2.associate_trunk_interface(BranchInterfaceId=branch_eni, TrunkInterfaceId=trunk_eni, VlanId=7)
    )
    assert code == "OperationNotPermitted", f"expected OperationNotPermitted, got {code}"
    expected_code_message = f"User {ctx.account} is not permitted to perform this operation"
    assert code_message == expected_code_message, f"expected message {expected_code_message!r}, got {code_message!r}"

    # Effect absent: no association was created, and the read side of the same API family is
    # gated identically -- DescribeTrunkInterfaceAssociations is rejected with the same code
    # rather than quietly answering with an (empty) list, which would be indistinguishable from
    # real association data leaking through to a principal that isn't supposed to see any.
    describe_code, describe_code_message = _error_code(
        lambda: ec2.describe_trunk_interface_associations(
            Filters=[{"Name": "trunk-interface-association.trunk-interface-id", "Values": [trunk_eni]}]
        )
    )
    assert describe_code == "OperationNotPermitted", f"expected OperationNotPermitted, got {describe_code}"
    expected_describe_code_message = f"User {ctx.account} is not permitted to perform this operation"
    assert describe_code_message == expected_describe_code_message, f"expected message {expected_describe_code_message!r}, got {describe_code_message!r}"


# ===== helpers =====
_GONE = frozenset({
    "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "InvalidNetworkInterfaceID.NotFound",
    "InvalidInstanceID.NotFound", "InvalidAttachmentID.NotFound", "InvalidVolume.NotFound",
})
_BUSY = frozenset({"DependencyViolation", "InvalidNetworkInterface.InUse", "VolumeInUse"})


def _cleanup(fn: Callable[[], Any], *done_codes: str) -> None:
    """Run one teardown call: a resource already gone (or a code in done_codes) returns; one AWS
    is still releasing is retried every 2 s for up to 30 s; any other error raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 30.0
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in _GONE or code in done_codes:
                return
            if code not in _BUSY or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error_code(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except Exception as exc:
        err = getattr(exc, "response", {}).get("Error")
        if not err:
            raise
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
