"""state-machine-directory-lifecycle-create-active-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "state-machine-directory-lifecycle-create-active-delete"
GROUP = "state-machine"
SERVICES = ["ds"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateMicrosoftAD returns a directory that is not yet Active, which then reaches Active, and
    DeleteDirectory drives it through Deleting until describes no longer return it."""
    # A Standard-edition Managed Microsoft AD takes tens of minutes to reach Active and then Deleted.
    directory_id = _create_microsoft_ad(ctx)

    # Real AWS never returns an Active directory synchronously from CreateDirectory.
    immediate_stage = _directory_stage(ctx, directory_id)
    assert immediate_stage in ("Requested", "Creating", "Created"), (
        f"expected a non-Active stage immediately after CreateMicrosoftAD, got {immediate_stage}"
    )

    active_stage = _wait_for_stage(ctx, directory_id, {"Active"}, timeout_s=2200)
    assert active_stage == "Active", f"expected directory to reach Active, got {active_stage}"

    ds = ctx.client("ds")
    ds.delete_directory(DirectoryId=directory_id)

    deleting_or_gone = _directory_stage(ctx, directory_id)
    assert deleting_or_gone in ("Deleting", None), (
        f"expected Deleting or already-removed right after DeleteDirectory, got {deleting_or_gone}"
    )

    _wait_for_gone(ctx, directory_id, timeout_s=600)


# ===== helpers =====


def _create_vpc_with_subnets(ctx):
    ec2 = ctx.client("ec2")
    tag = ctx.unique_name("sim2real-ds-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.0.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": tag}]}],
    )["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"][:2]]
    if len(azs) < 2:
        raise AssertionError("need at least 2 availability zones to create a test directory")
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.0.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": f"{tag}{i}"}]}],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)

    def _cleanup_network():
        for subnet_id in subnet_ids:
            try:
                _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "InvalidSubnetID.NotFound":
                    raise
        try:
            _delete_net(ec2, "delete_vpc", VpcId=vpc_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidVpcID.NotFound":
                raise

    ctx.on_cleanup(_cleanup_network)
    return vpc_id, subnet_ids


def _create_microsoft_ad(ctx, password="Sim2Real-TestPW1"):
    ds = ctx.client("ds")
    vpc_id, subnet_ids = _create_vpc_with_subnets(ctx)
    name = ctx.unique_name("sim2real-ds-") + ".test"
    directory_id = ds.create_microsoft_ad(
        Name=name,
        Password=password,
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Edition="Standard",
        Tags=[{"Key": "Name", "Value": name}],
    )["DirectoryId"]
    ctx.on_cleanup(lambda: _safe_delete_directory(ctx, directory_id))
    return directory_id


def _safe_delete_directory(ctx, directory_id):
    ds = ctx.client("ds")
    try:
        ds.delete_directory(DirectoryId=directory_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DirectoryDoesNotExistException",
            "EntityDoesNotExistException",
        ):
            raise


def _directory_stage(ctx, directory_id):
    ds = ctx.client("ds")
    try:
        resp = ds.describe_directories(DirectoryIds=[directory_id])
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityDoesNotExistException":
            return None
        raise
    descs = resp["DirectoryDescriptions"]
    return descs[0]["Stage"] if descs else None


def _wait_for_stage(ctx, directory_id, target_stages, timeout_s=2700, interval_s=20):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _directory_stage(ctx, directory_id)
        if last in target_stages:
            return last
        if last in ("Failed", "Impaired", "Inoperable") and last not in target_stages:
            raise AssertionError(f"directory {directory_id} reached unexpected stage {last}")
        time.sleep(interval_s)
    raise AssertionError(
        f"directory {directory_id} did not reach {target_stages} within {timeout_s}s (last={last})"
    )


def _wait_for_gone(ctx, directory_id, timeout_s=1800, interval_s=20):
    deadline = time.monotonic() + timeout_s
    last = "Deleting"
    while time.monotonic() < deadline:
        last = _directory_stage(ctx, directory_id)
        if last in (None, "Deleted"):
            return
        time.sleep(interval_s)
    raise AssertionError(f"directory {directory_id} was not removed within {timeout_s}s (last={last})")


# A directory in this VPC deletes asynchronously and leaves its ENIs behind for a while, so an
# immediate DeleteSubnet / DeleteVpc fails with DependencyViolation. Teardown waits (bounded) for the
# ENIs, retries DependencyViolation in one window shared by the check's network deletes, then raises
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
