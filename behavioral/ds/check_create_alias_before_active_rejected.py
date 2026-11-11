"""create-alias-before-active-rejected."""
from __future__ import annotations

import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "create-alias-before-active-rejected"
GROUP = "overly-permissive"
SERVICES = ["ds"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAlias on a directory not yet Active is rejected with InvalidParameterException and
    attaches no alias; once the same directory is Active the identical call succeeds and
    DescribeDirectories shows the alias, so the rejection is the Active-state precondition."""
    ds = ctx.client("ds")
    vpc_id, subnet_ids = _create_vpc_with_two_subnets(ctx)
    directory_id = _create_directory(ctx, ds, vpc_id, subnet_ids)

    alias = ctx.unique_name("sim2real-ds-alias-").replace("_", "-")

    # Break exactly one thing: CreateAlias before the directory has reached Active.
    code, message, request_id = _error(lambda: ds.create_alias(DirectoryId=directory_id, Alias=alias))
    assert code == "InvalidParameterException", code
    expected_message = (
        f"The directory must be active before an alias can be created for it. : RequestId: {request_id}"
    )
    assert message == expected_message, f"unexpected error message: {message!r}"

    # Effect absent: the directory never got the alias.
    described = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
    assert described.get("Alias") != alias, described.get("Alias")
    assert described["DirectoryId"] == directory_id, described.get("DirectoryId")
    assert described["Stage"] in ("Requested", "Creating", "Created", "Active"), described["Stage"]

    # Restore: wait for the directory to actually reach Active.
    _wait_for_directory_stage(directory_id, ds, {"Active"})

    # Assert the identical call now succeeds -- the discriminating positive control.
    resp = ds.create_alias(DirectoryId=directory_id, Alias=alias)
    assert resp["Alias"] == alias, resp

    # Terminal read: independent operation, at the destination.
    described_after = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
    assert described_after.get("Alias") == alias, described_after.get("Alias")


# ===== helpers =====

def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DirectoryDoesNotExistException",
            "EntityDoesNotExistException",
        ):
            raise


def _error(fn) -> tuple[str, str, str]:
    """(code, message, request id) of the ClientError fn raises; AssertionError if it succeeds."""
    try:
        result = fn()
    except ClientError as err:
        e = err.response["Error"]
        return e["Code"], e.get("Message", ""), err.response["ResponseMetadata"]["RequestId"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _ad_password() -> str:
    return "Sim2Real!" + secrets.token_hex(8) + "Aa1"


def _tag_spec(ctx, resource_type: str, kind: str):
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-ds-{kind}-")}],
    }


def _create_vpc_with_two_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.179.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc", "vpc")])["Vpc"]["VpcId"]

    def _cleanup_vpc():
        try:
            _delete_net(ec2, "delete_vpc", VpcId=vpc_id)
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidVpcID.NotFound":
                raise

    ctx.on_cleanup(_cleanup_vpc)
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
    az_names = [az["ZoneName"] for az in azs[:2]]
    if len(az_names) < 2:
        raise AssertionError("region does not have 2 available AZs")

    subnet_ids = []
    for i, az in enumerate(az_names):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.179.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec(ctx, "subnet", "subnet")],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)

        def _cleanup_subnet(sid=subnet_id):
            try:
                _delete_net(ec2, "delete_subnet", SubnetId=sid)
            except ClientError as e:
                if e.response["Error"]["Code"] != "InvalidSubnetID.NotFound":
                    raise

        ctx.on_cleanup(_cleanup_subnet)
    return vpc_id, subnet_ids


def _wait_for_directory_stage(directory_id, ds, target_stages, timeout_s=2700, interval_s=20):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        descs = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        last = descs[0]["Stage"] if descs else None
        if last in target_stages:
            return last
        if last in ("Failed", "Impaired", "Inoperable") and last not in target_stages:
            raise AssertionError(f"directory {directory_id} reached unexpected stage {last}")
        time.sleep(interval_s)
    raise AssertionError(
        f"directory {directory_id} did not reach {target_stages} within {timeout_s}s (last={last})"
    )


def _create_directory(ctx, ds, vpc_id, subnet_ids) -> str:
    # Simple AD (CreateDirectory Size=Small/Large) is no longer open to new customers
    # (real AWS rejects it with ClientException) -- use CreateMicrosoftAD instead. The
    # directory is deliberately probed with CreateAlias immediately after creation,
    # before waiting for Active, to hit the Active-state precondition under test.
    name = f"{ctx.unique_name('sim2real-ds-')}.example.com"
    directory_id = ds.create_microsoft_ad(
        Name=name,
        Password=_ad_password(),
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Edition="Standard",
    )["DirectoryId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ds.delete_directory(DirectoryId=directory_id)))
    return directory_id


# Subnet / VPC deletes fail with DependencyViolation while a deleted directory's ENIs linger: wait
# (bounded) for the ENIs to go, retry DependencyViolation in one window shared by all of a check's
# network deletes, then raise naming the ENIs still attached.
_NET_TEARDOWN_S = 1500.0  # the directory delete does not wait, so the network window takes the budget
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

