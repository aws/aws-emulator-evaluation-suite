"""op-contract-delete-traffic-mirror-session."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-delete-traffic-mirror-session"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteTrafficMirrorSession removes the session, which DescribeTrafficMirrorSessions then fails with
    InvalidTrafficMirrorSessionId.NotFound and its exact message, and frees its filter and target for a
    new session; a never-existing session ID fails with a TrafficMirrorSession NotFound code."""
    ec2 = ctx.client("ec2")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.102.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc")]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.102.1.0/24", TagSpecifications=[_tag_spec(ctx, "subnet")]
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))

    ami_id = _latest_amazon_linux_ami(ec2)

    source_eni = ec2.create_network_interface(
        SubnetId=subnet_id, TagSpecifications=[_tag_spec(ctx, "network-interface")]
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.delete_network_interface(
        NetworkInterfaceId=source_eni
    )))
    target_eni = ec2.create_network_interface(
        SubnetId=subnet_id, TagSpecifications=[_tag_spec(ctx, "network-interface")]
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.delete_network_interface(
        NetworkInterfaceId=target_eni
    )))

    # A Traffic Mirror source or target ENI must be attached to a running Nitro instance (an unattached
    # ENI fails with NetworkInterfaceNotSupported), so launch a small instance with each ENI as primary.
    source_instance_id = _launch_attached_instance(ec2, ctx, ami_id, source_eni)
    ctx.on_cleanup(lambda: _terminate_instance(ec2, source_instance_id))
    target_instance_id = _launch_attached_instance(ec2, ctx, ami_id, target_eni)
    ctx.on_cleanup(lambda: _terminate_instance(ec2, target_instance_id))

    _wait_for_running(ec2, source_instance_id)
    _wait_for_running(ec2, target_instance_id)

    filter_id = ec2.create_traffic_mirror_filter(
        TagSpecifications=[_tag_spec(ctx, "traffic-mirror-filter")]
    )["TrafficMirrorFilter"]["TrafficMirrorFilterId"]
    ctx.on_cleanup(lambda: ec2.delete_traffic_mirror_filter(TrafficMirrorFilterId=filter_id))

    target_id = ec2.create_traffic_mirror_target(
        NetworkInterfaceId=target_eni,
        TagSpecifications=[_tag_spec(ctx, "traffic-mirror-target")],
    )["TrafficMirrorTarget"]["TrafficMirrorTargetId"]
    ctx.on_cleanup(lambda: ec2.delete_traffic_mirror_target(TrafficMirrorTargetId=target_id))

    session_id = ec2.create_traffic_mirror_session(
        NetworkInterfaceId=source_eni,
        TrafficMirrorTargetId=target_id,
        TrafficMirrorFilterId=filter_id,
        SessionNumber=5,
        TagSpecifications=[_tag_spec(ctx, "traffic-mirror-session")],
    )["TrafficMirrorSession"]["TrafficMirrorSessionId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.delete_traffic_mirror_session(
        TrafficMirrorSessionId=session_id
    )))

    # Success path: the delete removes the session.
    resp = ec2.delete_traffic_mirror_session(TrafficMirrorSessionId=session_id)
    assert resp["TrafficMirrorSessionId"] == session_id, (
        f"expected delete to echo {session_id!r}, got {resp['TrafficMirrorSessionId']!r}"
    )

    code, message = _error(
        lambda: ec2.describe_traffic_mirror_sessions(TrafficMirrorSessionIds=[session_id])
    )
    assert code == "InvalidTrafficMirrorSessionId.NotFound", (
        f"expected InvalidTrafficMirrorSessionId.NotFound, got {code!r}"
    )
    assert message == f"{session_id} does not exist", message

    # Proves the target/filter were actually freed: a new session can reuse them.
    replacement_id = ec2.create_traffic_mirror_session(
        NetworkInterfaceId=source_eni,
        TrafficMirrorTargetId=target_id,
        TrafficMirrorFilterId=filter_id,
        SessionNumber=5,
        TagSpecifications=[_tag_spec(ctx, "traffic-mirror-session")],
    )["TrafficMirrorSession"]["TrafficMirrorSessionId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.delete_traffic_mirror_session(
        TrafficMirrorSessionId=replacement_id
    )))
    assert replacement_id != session_id, (
        f"expected a fresh session id distinct from the deleted {session_id!r}, "
        f"got the same id back"
    )

    # Error boundary: a session ID that never existed, with the valid "tms-" prefix; a malformed prefix
    # fails ID validation first with InvalidParameterValue.
    code, _message = _error(
        lambda: ec2.delete_traffic_mirror_session(
            TrafficMirrorSessionId="tms-00000000000000000"
        )
    )
    assert "TrafficMirrorSession" in code and code.endswith("NotFound"), (
        f"expected a TrafficMirrorSession NotFound code, got {code!r}"
    )


# ===== helpers =====
def _best_effort(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidNetworkInterfaceID.NotFound",
            "InvalidTrafficMirrorSessionId.NotFound",
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


def _tag_spec(ctx: Any, resource_type: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-behav-{resource_type}-")}],
    }


def _launch_attached_instance(ec2: Any, ctx: Any, ami_id: str, eni_id: str) -> str:
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        NetworkInterfaces=[{"NetworkInterfaceId": eni_id, "DeviceIndex": 0}],
        TagSpecifications=[_tag_spec(ctx, "instance")],
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


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its error code and message. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


# AWS-managed ENIs leave a VPC asynchronously after their owner's delete returns, so DeleteSubnet,
# DeleteSecurityGroup and DeleteVpc can fail with DependencyViolation: wait for the ENIs to go,
# retry inside the same window, and raise naming any ENI still attached.
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
