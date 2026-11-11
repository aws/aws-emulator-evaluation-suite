"""directory-data-access-server-enforced-toggle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "directory-data-access-server-enforced-toggle"
GROUP = "server-side"
SERVICES = ["ds"]

_PASSWORD = "Sim2Real-Dataaccess-2024!"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """EnableDirectoryDataAccess/DisableDirectoryDataAccess drive a server-side data-plane
    gate whose state DescribeDirectoryDataAccess authoritatively reflects, not a
    client-side flag.
    """
    ds = ctx.client("ds")
    vpc_id, subnet_ids = _create_vpc_with_subnets(ctx)
    name = f"{ctx.unique_name('sim2real-ds-dataaccess').rstrip('-').lower()}.example.com"
    directory_id = ds.create_microsoft_ad(
        Name=name,
        Password=_PASSWORD,
        Edition="Standard",
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
    )["DirectoryId"]
    ctx.on_cleanup(lambda: _delete_directory_and_wait(ds, directory_id))

    _wait_directory_active(ds, directory_id, timeout_s=2700.0)

    baseline = ds.describe_directory_data_access(DirectoryId=directory_id)["DataAccessStatus"]
    assert baseline == "Disabled", f"expected a freshly created directory to start Disabled, got {baseline}"

    ds.enable_directory_data_access(DirectoryId=directory_id)
    status = _wait_data_access_status(ds, directory_id, {"Enabled"}, timeout_s=900.0)
    assert status == "Enabled"

    # Bonus depth: re-enabling an already-enabled gate is rejected by the server, and the
    # state is left exactly as it was (no double-transition, no silent success).
    code, message, request_id = _error(lambda: ds.enable_directory_data_access(DirectoryId=directory_id))
    assert code == "DirectoryInDesiredStateException", f"expected DirectoryInDesiredStateException, got {code}"
    expected_message = f"Directory {directory_id} is already in the desired state. : RequestId: {request_id}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    assert ds.describe_directory_data_access(DirectoryId=directory_id)["DataAccessStatus"] == "Enabled"

    ds.disable_directory_data_access(DirectoryId=directory_id)
    status_after_disable = _wait_data_access_status(ds, directory_id, {"Disabled"}, timeout_s=900.0)
    assert status_after_disable == "Disabled"

    # Full round trip: the gate can be flipped back on again after being disabled.
    ds.enable_directory_data_access(DirectoryId=directory_id)
    status_again = _wait_data_access_status(ds, directory_id, {"Enabled"}, timeout_s=900.0)
    assert status_again == "Enabled"


# ===== helpers =====
def _error(fn):
    """Call fn(); return the (Code, Message, RequestId) of the ClientError it raises. An
    unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return (
            err.response["Error"]["Code"],
            err.response["Error"].get("Message"),
            err.response.get("ResponseMetadata", {}).get("RequestId"),
        )
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_vpc_with_subnets(ctx, cidr_prefix: str = "10.96"):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock=f"{cidr_prefix}.0.0/16",
        TagSpecifications=[
            {
                "ResourceType": "vpc",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ds-vpc-")}],
            }
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    azs = [a["ZoneName"] for a in ec2.describe_availability_zones()["AvailabilityZones"]][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"{cidr_prefix}.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {
                    "ResourceType": "subnet",
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ds-subnet-")}],
                }
            ],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _wait_directory_active(ds, directory_id, timeout_s=2700.0, interval_s=30.0):
    deadline = time.monotonic() + timeout_s
    stage = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        stage = desc["Stage"]
        if stage == "Active":
            return desc
        if stage == "Failed":
            raise AssertionError(f"directory {directory_id} entered Failed stage")
        time.sleep(interval_s)
    raise AssertionError(f"directory {directory_id} did not reach Active (last stage={stage})")


def _wait_data_access_status(ds, directory_id, terminal_statuses, timeout_s=900.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = ds.describe_directory_data_access(DirectoryId=directory_id)["DataAccessStatus"]
        if status in terminal_statuses:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"DataAccessStatus did not reach {terminal_statuses} within {timeout_s}s (last={status})")


# Bounded so the directory wait plus the network teardown window fit the 900s
# cleanup budget; the network deletes keep waiting for the directory's ENIs after this returns.
def _delete_directory_and_wait(ds, directory_id, timeout_s=240.0, interval_s=20.0):
    from botocore.exceptions import ClientError

    try:
        ds.delete_directory(DirectoryId=directory_id)
    except ClientError as err:
        if err.response["Error"]["Code"] == "EntityDoesNotExistException":
            return
        raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            found = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "EntityDoesNotExistException":
                return
            raise
        if not found or found[0].get("Stage") == "Deleted":
            return
        time.sleep(interval_s)


# AWS-managed ENIs leave a VPC asynchronously after their owner's delete returns, so a network
# delete waits (bounded, within the cleanup budget) for them and retries DependencyViolation, then
# raises naming the ENIs still attached. Teardown-only: run() never calls this.
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
