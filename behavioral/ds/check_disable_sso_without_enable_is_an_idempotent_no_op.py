"""disable-sso-without-enable-is-an-idempotent-no-op."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disable-sso-without-enable-is-an-idempotent-no-op"
GROUP = "state-machine"
SERVICES = ["ds"]

_DS_PASSWORD = "Sim2Real-Test-Pwd-1!"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisableSso on a directory that never had SSO enabled succeeds and leaves SsoEnabled false;
    enabling then disabling SSO on the same directory flips the flag both ways.

    Reference: https://docs.aws.amazon.com/directoryservice/latest/devguide/API_DisableSso.html"""
    _ds_slow_gate(ctx)

    ds = ctx.client("ds")
    vpc_id, subnet_ids = _create_vpc_for_directory(ctx)
    directory_id = _create_microsoft_ad(ctx, vpc_id, subnet_ids)
    _wait_for_stage(ctx, directory_id, {"Active"}, timeout_s=2700.0, interval_s=30.0)

    desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
    assert desc.get("SsoEnabled", False) is False, "a freshly created directory must not have SSO enabled"

    try:
        ds.disable_sso(DirectoryId=directory_id)
    except ClientError as exc:
        raise AssertionError(
            f"expected DisableSso on a never-enabled directory to succeed as a no-op on real AWS, got {exc.response['Error']['Code']}"
        ) from exc

    desc_after = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
    assert desc_after.get("SsoEnabled", False) is False, (
        "SsoEnabled must still be false after the no-op DisableSso call"
    )

    # EnableSso requires an alias first ("An alias is required before enabling SSO").
    alias = ctx.unique_name("sim2real-ds-disable-sso-").rstrip("-").lower()
    ds.create_alias(DirectoryId=directory_id, Alias=alias)
    ds.enable_sso(DirectoryId=directory_id, UserName="Admin", Password=_DS_PASSWORD)
    _wait_for_sso_state(ctx, directory_id, True, timeout_s=300.0)
    ds.disable_sso(DirectoryId=directory_id, UserName="Admin", Password=_DS_PASSWORD)
    _wait_for_sso_state(ctx, directory_id, False, timeout_s=300.0)


def _ds_slow_gate(ctx) -> None:
    # Managed Microsoft AD takes ~20-45 minutes to provision and bills for its lifetime.
    return


def _create_vpc_for_directory(ctx):
    ec2 = ctx.client("ec2")
    vpc = ec2.create_vpc(
        CidrBlock="10.190.0.0/16",
        TagSpecifications=[
            {
                "ResourceType": "vpc",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ds-vpc-")}],
            }
        ],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    azs = [
        az["ZoneName"]
        for az in ec2.describe_availability_zones(
            Filters=[{"Name": "zone-type", "Values": ["availability-zone"]}]
        )["AvailabilityZones"]
        if az["State"] == "available"
    ][:2]
    if len(azs) < 2:
        raise AssertionError(f"region {ctx.region} does not expose 2 available AZs required for a DS directory VPC")

    subnet_ids = []
    for i, az in enumerate(azs):
        subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.190.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {
                    "ResourceType": "subnet",
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ds-subnet-")}],
                }
            ],
        )["Subnet"]
        subnet_id = subnet["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _create_microsoft_ad(ctx, vpc_id, subnet_ids, edition: str = "Standard") -> str:
    ds = ctx.client("ds")
    name = f"{ctx.unique_name('sim2real-ds-')}.test"
    resp = ds.create_microsoft_ad(
        Name=name,
        Password=_DS_PASSWORD,
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Edition=edition,
    )
    directory_id = resp["DirectoryId"]
    ctx.on_cleanup(lambda: _delete_directory(ctx, directory_id))
    return directory_id


def _delete_directory(ctx, directory_id) -> None:
    """Delete the directory and wait until it is gone; with the network teardown it fits the
    1800 s cleanup budget. DeleteDirectory is retried while the directory is still being created."""
    ds = ctx.client("ds")
    deadline = time.monotonic() + 1140.0
    while True:
        try:
            ds.delete_directory(DirectoryId=directory_id)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "EntityDoesNotExistException":
                return
            if code not in ("ClientException", "InvalidParameterException") or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    _wait_for_stage(ctx, directory_id, {"Deleted"}, timeout_s=max(deadline - time.monotonic(), 0.0), interval_s=2.0)


def _wait_for_stage(ctx, directory_id, target_stages, timeout_s=2700.0, interval_s=30.0):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "EntityDoesNotExistException" and "Deleted" in target_stages:
                return "Deleted"
            raise
        if desc:
            stage = desc[0]["Stage"]
            if stage in target_stages:
                return stage
            if stage == "Failed":
                raise AssertionError(f"directory {directory_id} entered Failed stage while waiting for {target_stages}")
        elif "Deleted" in target_stages:
            return "Deleted"
        if time.monotonic() >= deadline:
            raise AssertionError(f"directory {directory_id} did not reach {target_stages} within {timeout_s}s")
        time.sleep(interval_s)


def _wait_for_sso_state(ctx, directory_id, expected: bool, timeout_s=300.0, interval_s=10.0):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        if desc.get("SsoEnabled", False) == expected:
            return
        time.sleep(interval_s)
    raise AssertionError(f"SsoEnabled for {directory_id} never became {expected} within {timeout_s}s")


# Asynchronously deleted resources (load balancers, directories, endpoints, ...) leave ENIs in the
# subnet / security group for a while, so an immediate delete fails with DependencyViolation. Wait
# (bounded) for the ENIs to go, retry DependencyViolation in the same window, then raise naming the
# ENIs still attached. The window is shared by all of one check's network deletes.
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
