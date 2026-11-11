"""volume-delete-while-attached-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError


from behavioral_harness import tags


#: AWS-owned public parameter; the catalog-ami-resolvable member grades its resolution.
_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
#: The EC2 service-class budget for one state wait; the harness deadline bounds the run.
POLL_BUDGET_S = 600.0


def _catalog_ami(ctx):
    """ImageId of the catalog AMI (same GetParameter the catalog-ami-resolvable member grades)."""
    try:
        return ctx.client("ssm").get_parameter(Name=_AMI_PARAM)["Parameter"]["Value"]
    except ClientError as exc:
        raise AssertionError(f"prerequisite catalog-ami: GetParameter({_AMI_PARAM}) failed: {exc}") from exc


def _wait_instance_state(ec2, instance_id, state, timeout_s=POLL_BUDGET_S):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = ec2.describe_instances(InstanceIds=[instance_id])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidInstanceID.NotFound":
                last = "__not_yet_visible__"
                time.sleep(3)
                continue
            raise
        reservations = resp.get("Reservations", [])
        if not reservations or not reservations[0].get("Instances"):
            last = "__not_yet_visible__"
        else:
            last = reservations[0]["Instances"][0]["State"]["Name"]
        if last == state:
            return last
        time.sleep(3)
    raise AssertionError(
        f"instance {instance_id} did not reach {state!r} within {timeout_s}s (last {last!r})"
    )


def _get_az(ec2, region, instance_type="t3.micro"):
    """An available AZ of *region* that actually offers *instance_type* (falls back to any)."""
    zones = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "region-name", "Values": [region]}]
        ).get("AvailabilityZones", [])
        if z.get("State", "available") == "available"
        and z.get("ZoneType", "availability-zone") == "availability-zone"
    ]
    if not zones:
        raise AssertionError("no availability zones available")
    try:
        offerings = ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [instance_type]}],
        ).get("InstanceTypeOfferings", [])
        offered = {o["Location"] for o in offerings}
        for z in zones:
            if z in offered:
                return z
    except Exception:
        pass
    return zones[0]


def _own_subnet(ctx, run_tag):
    """Return (subnet_id, az) of a VPC+subnet this check creates, pinned to one AZ of ctx.region
    that offers t3.micro, and tears down itself."""
    ec2 = ctx.client("ec2")
    az = _get_az(ec2, ctx.region)
    vpc_id = ec2.create_vpc(
        CidrBlock="10.212.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": [run_tag]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.212.1.0/24", AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [run_tag]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    return subnet_id, az


def _wait_volume_state(ec2, volume_id, state, timeout_s=POLL_BUDGET_S):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidVolume.NotFound":
                last = "__not_yet_visible__"
                time.sleep(2)
                continue
            raise
        if last == state:
            return last
        time.sleep(2)
    raise AssertionError(f"volume {volume_id} did not reach {state!r} within {timeout_s}s (last {last!r})")


def _cleanup_volume(ec2, volume_id):
    """Teardown: force-detach, wait available, delete; only not-found / already-detached is tolerated."""
    def _code(exc):
        return exc.response.get("Error", {}).get("Code")

    try:
        ec2.detach_volume(VolumeId=volume_id, Force=True)
    except ClientError as exc:
        if _code(exc) not in ("InvalidVolume.NotFound", "IncorrectState"):
            raise
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            state = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"]
        except ClientError as exc:
            if _code(exc) != "InvalidVolume.NotFound":
                raise
            return
        if state == "available":
            break
        time.sleep(2)
    try:
        ec2.delete_volume(VolumeId=volume_id)
    except ClientError as exc:
        if _code(exc) != "InvalidVolume.NotFound":
            raise

CHECK = "volume-delete-while-attached-fails"
GROUP = 'overly-permissive'
SERVICES = ['ec2']

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteVolume on a volume that is still attached must fail with VolumeInUse (overly-permissive check)."""
    ec2 = ctx.client("ec2")
    run_tag = {"Key": "sim2real-check", "Value": ctx.unique_name("vol-")}
    subnet_id, az = _own_subnet(ctx, run_tag)
    ami = _catalog_ami(ctx)
    instance_id = ec2.run_instances(
        ImageId=ami, InstanceType="t3.micro", MinCount=1, MaxCount=1, SubnetId=subnet_id,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "sim2real", "Value": "1"}, run_tag]}],
    )["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    _wait_instance_state(ec2, instance_id, "running")

    volume_id = ec2.create_volume(AvailabilityZone=az, Size=1, TagSpecifications=[{"ResourceType": "volume", "Tags": [{"Key": "sim2real", "Value": "1"}, run_tag]}])["VolumeId"]
    ctx.on_cleanup(lambda: _cleanup_volume(ec2, volume_id))
    _wait_volume_state(ec2, volume_id, "available")
    ec2.attach_volume(VolumeId=volume_id, InstanceId=instance_id, Device="/dev/sdf")
    _wait_volume_state(ec2, volume_id, "in-use")

    try:
        accepted = ec2.delete_volume(VolumeId=volume_id)
    except ClientError as exc:
        refusal = exc.response
    else:
        raise AssertionError(f"DeleteVolume on an attached volume was expected to be refused, but it SUCCEEDED: {accepted!r}")
    _assert_error(refusal, "VolumeInUse", volume_id)
    expected_message = f"Volume {volume_id} is currently attached to {{{instance_id}}}"
    assert refusal.get("Error", {}).get("Message") == expected_message, (
        f"expected the message {expected_message!r}, got {refusal.get('Error', {}).get('Message')!r}"
    )

    # effect absent: the rejected delete must not have mutated the volume — it is still
    # in-use and still attached to the same instance, via an independent read
    survivor = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]
    assert survivor["State"] == "in-use", (
        f"rejected DeleteVolume must leave {volume_id} 'in-use', got {survivor['State']!r}"
    )
    attached_ids = {a["InstanceId"] for a in survivor.get("Attachments", [])}
    assert instance_id in attached_ids, (
        f"rejected DeleteVolume must leave {volume_id} attached to {instance_id}, "
        f"attachments now: {survivor.get('Attachments')}"
    )

    # restore: detach the volume, then the identical DeleteVolume call must now succeed
    ec2.detach_volume(VolumeId=volume_id, InstanceId=instance_id)
    _wait_volume_state(ec2, volume_id, "available")
    ec2.delete_volume(VolumeId=volume_id)

    # deletes prove gone: an independent read now reports the id unknown, and a further
    # mutation on the dead id also fails with the specific not-found code
    # Gone beat 1: DescribeVolumes by id converges to InvalidVolume.NotFound.
    _assert_error(_wait_volume_gone(ec2, volume_id), "InvalidVolume.NotFound", volume_id)
    # Gone beat 2: no volume carrying this run's tag is listed.
    tagged = ec2.describe_volumes(Filters=[{"Name": f"tag:{run_tag['Key']}", "Values": [run_tag["Value"]]}])["Volumes"]
    assert volume_id not in [v["VolumeId"] for v in tagged], "deleted volume still listed by its run tag"
    # Gone beat 3: a mutation on the dead id fails with the specific not-found code.
    try:
        result = ec2.detach_volume(VolumeId=volume_id, InstanceId=instance_id)
    except ClientError as exc:
        # DetachVolume on the deleted id is graded on its code (InvalidVolume.NotFound), any 4xx status
        # and a non-empty message.
        _assert_error(exc.response, "InvalidVolume.NotFound", None, status=None)
    else:
        raise AssertionError(f"DetachVolume on the deleted volume SUCCEEDED: {result!r}")


def _assert_error(resp, code, subject, status=400):
    """Grade a refusal on code + HTTP status (any 4xx when status is None) + the exact message
    (naming the subject id if given)."""
    err = resp.get("Error", {})
    got_status = resp.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert err.get("Code") == code, f"expected {code}, got {err.get('Code')!r}"
    if status is None:
        assert isinstance(got_status, int) and 400 <= got_status < 500, f"expected a 4xx for {code}, got {got_status!r}"
    else:
        assert got_status == status, f"expected HTTP {status} for {code}, got {got_status!r}"
    assert err.get("Message"), f"expected a non-empty {code} message, got {err!r}"
    if subject is not None:
        assert subject in err["Message"], f"expected the {code} message to name {subject!r}, got {err['Message']!r}"


def _wait_volume_gone(ec2, volume_id, timeout_s=POLL_BUDGET_S):
    """Poll DescribeVolumes until it refuses the id; return that ClientError response."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"]
        except ClientError as exc:
            return exc.response
        time.sleep(2)
    raise AssertionError(f"volume {volume_id} still describable as {last!r} after {timeout_s}s")


# ===== helpers =====

# EC2 network teardown: an asynchronously deleted dependent leaves its ENIs in the subnet / security
# group, so each delete retries DependencyViolation while they drain, inside one window shared by the
# check's network deletes and the suite's cleanup budget, then raises naming the ENIs still attached.
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
        _time.sleep(10)
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
        _time.sleep(10)


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
