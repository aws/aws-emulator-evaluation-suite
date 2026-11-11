"""op-contract-delete-traffic-mirror-target."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-delete-traffic-mirror-target"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTrafficMirrorTarget is rejected while the target backs an active session
    (TrafficMirrorTargetInUse); once unreferenced it deletes and is confirmed gone."""
    ec2 = ctx.client("ec2")
    tag = [{"Key": "sim2real", "Value": "1"}]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.101.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": tag}]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.101.1.0/24",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tag}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))

    ami_id = _latest_amazon_linux_ami(ec2)

    source_eni = ec2.create_network_interface(
        SubnetId=subnet_id,
        TagSpecifications=[{"ResourceType": "network-interface", "Tags": tag}],
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.delete_network_interface(
        NetworkInterfaceId=source_eni
    )))
    target_eni = ec2.create_network_interface(
        SubnetId=subnet_id,
        TagSpecifications=[{"ResourceType": "network-interface", "Tags": tag}],
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.delete_network_interface(
        NetworkInterfaceId=target_eni
    )))

    # Traffic Mirror sources/targets that are network interfaces must be attached to a
    # supported (Nitro-based) running instance; a freshly-created, unattached ENI is rejected
    # with NetworkInterfaceNotSupported. Attach each ENI by launching a small Nitro instance
    # with it as the primary interface.
    source_instance_id = _launch_attached_instance(ec2, ami_id, source_eni, tag)
    ctx.on_cleanup(lambda: _terminate_instance(ec2, source_instance_id))
    target_instance_id = _launch_attached_instance(ec2, ami_id, target_eni, tag)
    ctx.on_cleanup(lambda: _terminate_instance(ec2, target_instance_id))

    _wait_for_running(ec2, source_instance_id)
    _wait_for_running(ec2, target_instance_id)

    filter_id = ec2.create_traffic_mirror_filter(
        TagSpecifications=[{"ResourceType": "traffic-mirror-filter", "Tags": tag}]
    )["TrafficMirrorFilter"]["TrafficMirrorFilterId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.delete_traffic_mirror_filter(
        TrafficMirrorFilterId=filter_id
    )))

    target_id = ec2.create_traffic_mirror_target(
        NetworkInterfaceId=target_eni,
        TagSpecifications=[{"ResourceType": "traffic-mirror-target", "Tags": tag}],
    )["TrafficMirrorTarget"]["TrafficMirrorTargetId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.delete_traffic_mirror_target(
        TrafficMirrorTargetId=target_id
    )))

    session_id = ec2.create_traffic_mirror_session(
        NetworkInterfaceId=source_eni,
        TrafficMirrorTargetId=target_id,
        TrafficMirrorFilterId=filter_id,
        SessionNumber=1,
        TagSpecifications=[{"ResourceType": "traffic-mirror-session", "Tags": tag}],
    )["TrafficMirrorSession"]["TrafficMirrorSessionId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.delete_traffic_mirror_session(
        TrafficMirrorSessionId=session_id
    )))

    # Error boundary: the target is still referenced by an active session. Real EC2 rejects
    # this with the traffic-mirror-specific "TrafficMirrorTargetInUse" code, not the generic
    # DependencyViolation used by other resource families.
    code, msg = _client_error(lambda: ec2.delete_traffic_mirror_target(TrafficMirrorTargetId=target_id))
    assert code == "TrafficMirrorTargetInUse", f"expected TrafficMirrorTargetInUse, got {code!r}"
    expected_msg = f"Cannot delete {target_id}. Target is in use by {session_id}"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # The rejected delete must not have taken effect: the target is still there.
    still_there = ec2.describe_traffic_mirror_targets(TrafficMirrorTargetIds=[target_id])[
        "TrafficMirrorTargets"
    ]
    assert len(still_there) == 1 and still_there[0]["TrafficMirrorTargetId"] == target_id, (
        f"expected the in-use target to still exist after the rejected delete, got {still_there!r}"
    )

    # Once the session is removed, the target is free to delete.
    ec2.delete_traffic_mirror_session(TrafficMirrorSessionId=session_id)

    resp = ec2.delete_traffic_mirror_target(TrafficMirrorTargetId=target_id)
    assert resp["TrafficMirrorTargetId"] == target_id, (
        f"expected DeleteTrafficMirrorTarget to echo {target_id!r}, got {resp!r}"
    )

    code, msg = _client_error(
        lambda: ec2.describe_traffic_mirror_targets(TrafficMirrorTargetIds=[target_id])
    )
    assert code == "InvalidTrafficMirrorTargetId.NotFound", (
        f"expected a TrafficMirrorTarget NotFound code, got {code!r}"
    )
    expected_msg = f"{target_id} does not exist"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # A second delete of the now-gone target must also fail, not resurrect or no-op it.
    second_code, second_msg = _client_error(
        lambda: ec2.delete_traffic_mirror_target(TrafficMirrorTargetId=target_id)
    )
    assert second_code == "InvalidTrafficMirrorTargetId.NotFound", (
        f"expected a TrafficMirrorTarget NotFound code on double-delete, got {second_code!r}"
    )
    expected_msg = f"{target_id} does not exist"
    assert second_msg == expected_msg, f"expected message {expected_msg!r}, got {second_msg!r}"


# ===== helpers =====
def _best_effort(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidNetworkInterfaceID.NotFound",
            "InvalidTrafficMirrorFilterId.NotFound",
            "InvalidTrafficMirrorSessionId.NotFound",
            "InvalidTrafficMirrorTargetId.NotFound",
        ):
            raise


def _latest_amazon_linux_ami(ec2: Any) -> str:
    resp = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["amzn2-ami-hvm-*-x86_64-gp2"]},
            {"Name": "state", "Values": ["available"]},
            {"Name": "root-device-type", "Values": ["ebs"]},
        ],
    )
    images = resp["Images"]
    images.sort(key=lambda img: img["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _launch_attached_instance(
    ec2: Any, ami_id: str, eni_id: str, tag: list[dict[str, str]]
) -> str:
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        NetworkInterfaces=[{"NetworkInterfaceId": eni_id, "DeviceIndex": 0}],
        TagSpecifications=[{"ResourceType": "instance", "Tags": tag}],
    )
    return resp["Instances"][0]["InstanceId"]


def _wait_for_running(ec2: Any, instance_id: str, timeout_s: float = 300.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = ec2.describe_instances(InstanceIds=[instance_id])
            last = resp["Reservations"][0]["Instances"][0]["State"]["Name"]
        except Exception:
            last = None
        if last == "running":
            return
        time.sleep(5)
    raise AssertionError(f"instance {instance_id} not running within {timeout_s}s, last={last!r}")


def _terminate_instance(ec2: Any, instance_id: str) -> None:
    """Terminate and wait (2 s polls, 120 s) for terminated; an instance already gone is fine."""
    try:
        ec2.terminate_instances(InstanceIds=[instance_id])
        deadline = time.monotonic() + 120
        while True:
            resp = ec2.describe_instances(InstanceIds=[instance_id])
            state = resp["Reservations"][0]["Instances"][0]["State"]["Name"]
            if state == "terminated":
                return
            if time.monotonic() >= deadline:
                raise AssertionError(f"instance {instance_id} still {state!r} 120 s after TerminateInstances")
            time.sleep(2)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
            raise


def _client_error(fn: Callable[[], Any]) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


# AWS-managed ENIs (endpoints, load balancers, instances) leave a VPC asynchronously after their
# owner's delete returns, so DeleteSubnet/DeleteSecurityGroup/DeleteVpc can fail with
# DependencyViolation. Wait (bounded) for the ENIs to go, retry inside the same window, and raise
# naming any ENIs still attached. Teardown-only: run() never calls this.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(2)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(2)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
