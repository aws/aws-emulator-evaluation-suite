"""state-machine-directory-create-active-delete-404."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "state-machine-directory-create-active-delete-404"
GROUP = "state-machine"
SERVICES = ["ds"]

_PASSWORD = "Sim2Real!Test2024"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A directory goes Requested/Creating -> Active; after DeleteDirectory completes,
    DescribeDirectories answers an empty list and a second mutating call on the id 404s."""
    ds = ctx.client("ds")
    name = f"{ctx.unique_name('sim2realds')}.test"
    # NOTE: CreateDirectory provisions Simple AD, which real AWS now rejects for new
    # customers ("Simple AD is no longer open to new customers"). CreateMicrosoftAD is the
    # supported equivalent for exercising the same Create -> Active -> Delete -> 404
    # lifecycle on DirectoryId/Stage/DescribeDirectories.
    directory_id, vpc_id, subnet_ids = _create_microsoft_ad_with_az_retry(ctx, ds, name)

    cleanup_done = {"value": False}

    def _cleanup():
        if cleanup_done["value"]:
            return
        try:
            ds.delete_directory(DirectoryId=directory_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "EntityDoesNotExistException":
                raise

    ctx.on_cleanup(_cleanup)

    desc = _wait_for_stage(ctx, directory_id, {"Active"}, timeout_s=3000)
    # The independent read returns what this check supplied at create.
    assert desc.get("Name") == name, f"Name {desc.get('Name')!r}, expected {name!r}"
    assert desc.get("Type") == "MicrosoftAD", f"Type {desc.get('Type')!r}, expected 'MicrosoftAD'"
    assert desc.get("Edition") == "Standard", f"Edition {desc.get('Edition')!r}, expected 'Standard'"
    vpc_settings = desc.get("VpcSettings") or {}
    assert vpc_settings.get("VpcId") == vpc_id, (
        f"VpcSettings.VpcId {vpc_settings.get('VpcId')!r}, expected {vpc_id!r}")
    assert set(vpc_settings.get("SubnetIds") or []) == set(subnet_ids), (
        f"VpcSettings.SubnetIds {vpc_settings.get('SubnetIds')!r}, expected {sorted(subnet_ids)!r}")

    ds.delete_directory(DirectoryId=directory_id)
    cleanup_done["value"] = True  # delete already issued; avoid a second delete in cleanup

    # Real AWS does not raise EntityDoesNotExistException from DescribeDirectories once a
    # directory is fully gone -- it answers 200 with an empty DirectoryDescriptions list.
    code, status = _wait_for_not_found(ctx, directory_id, timeout_s=1500)
    assert (code, status) == ("EmptyDescription", 200), (
        f"DescribeDirectories on the deleted directory must answer an empty list (HTTP 200), "
        f"got {code} HTTP {status}"
    )

    listed = _all_directory_ids(ds)
    assert directory_id not in listed, (
        f"the deleted directory is still in the unfiltered DescribeDirectories listing ({len(listed)} ids)"
    )

    # The id is not just absent from reads -- a mutation against it fails the same way,
    # proving it is genuinely dead rather than merely dropped from one API's listing.
    try:
        ds.delete_directory(DirectoryId=directory_id)
    except ClientError as exc:
        second_delete = exc.response
    else:
        raise AssertionError(f"a second DeleteDirectory against the dead id {directory_id} succeeded")
    second_delete_code = second_delete["Error"]["Code"]
    assert second_delete_code == "EntityDoesNotExistException", (
        f"a second DeleteDirectory against the dead id returned {second_delete_code!r}, "
        "not EntityDoesNotExistException"
    )
    status = second_delete["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 400, f"a second DeleteDirectory against the dead id returned HTTP {status}, not 400"
    got_message = second_delete["Error"].get("Message") or ""
    request_id = second_delete["ResponseMetadata"]["RequestId"]
    expected_message = f"Directory: '{directory_id}' does not exist. : RequestId: {request_id}"
    assert got_message == expected_message, f"expected the message {expected_message!r}, got {got_message!r}"


def _all_directory_ids(ds):
    """Every DirectoryId DescribeDirectories lists with no id filter, across every page."""
    ids, kwargs = [], {}
    while True:
        page = ds.describe_directories(**kwargs)
        ids.extend(d["DirectoryId"] for d in page["DirectoryDescriptions"])
        token = page.get("NextToken")
        if not token:
            return ids
        kwargs = {"NextToken": token}


# ===== helpers =====
def _create_microsoft_ad_with_az_retry(ctx, ds, name):
    """Directory Service does not support every AZ that EC2 reports as available (real AWS
    can reject one as "capacity constrained" for directory placement); a VPC/AZ pair that is
    fine for EC2 can still 400. Rotate to the next AZ pair of the check's own VPC whenever DS
    specifically rejects the placement -- never on any other error."""
    tried_pairs: set[frozenset] = set()
    last_error = None
    for vpc_id, subnet_ids, az_pair in _candidate_vpc_subnet_pairs(ctx):
        if az_pair in tried_pairs:
            continue
        tried_pairs.add(az_pair)
        try:
            directory_id = ds.create_microsoft_ad(
                Name=name,
                Password=_PASSWORD,
                VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
                Edition="Standard",
                Tags=[{"Key": "sim2real", "Value": "behavioral"}, {"Key": "sim2real-check", "Value": CHECK}],
            )["DirectoryId"]
            return directory_id, vpc_id, subnet_ids
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ClientException" and "Availability Zone" in str(exc):
                last_error = exc
                continue
            raise
    raise AssertionError(
        f"no AZ pair usable for a DS directory after trying {len(tried_pairs)}: {last_error}"
    )


def _candidate_vpc_subnet_pairs(ctx):
    """Yield (vpc_id, [subnet_id, subnet_id], frozenset({az, az})) candidates from a VPC this
    check creates, with one subnet in each of up to four available AZs, so DS can be offered
    another distinct-AZ pair when it rejects one for placement."""
    vpc_id, by_az = _create_dedicated_vpc_and_subnets(ctx)
    az_names = sorted(by_az)
    for i in range(len(az_names)):
        for j in range(i + 1, len(az_names)):
            a, b = az_names[i], az_names[j]
            yield vpc_id, [by_az[a], by_az[b]], frozenset({a, b})


def _create_dedicated_vpc_and_subnets(ctx):
    ec2 = ctx.client("ec2")
    tags = [{"Key": "Name", "Value": ctx.unique_name("sim2real-ds-")}, {"Key": "sim2real-check", "Value": CHECK}]
    vpc_id = ec2.create_vpc(CidrBlock="10.182.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": tags}])[
        "Vpc"
    ]["VpcId"]

    def _cleanup_vpc():
        _delete_net(ec2, "delete_vpc", VpcId=vpc_id)

    ctx.on_cleanup(_cleanup_vpc)
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
    az_names = sorted(az["ZoneName"] for az in azs if az.get("ZoneType", "availability-zone") == "availability-zone")[:4]
    if len(az_names) < 2:
        raise AssertionError(f"region offers {len(az_names)} available AZs; a DS directory needs 2")

    by_az = {}
    for i, az in enumerate(az_names):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.182.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": tags}],
        )["Subnet"]["SubnetId"]
        by_az[az] = subnet_id

        def _cleanup_subnet(sid=subnet_id):
            _delete_net(ec2, "delete_subnet", SubnetId=sid)

        ctx.on_cleanup(_cleanup_subnet)
    return vpc_id, by_az


def _wait_for_stage(ctx, directory_id, target_stages, timeout_s=1500, interval_s=20):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    stage = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        stage = desc["Stage"]
        if stage in target_stages:
            return desc
        if stage in ("Failed", "Inoperable"):
            raise AssertionError(f"directory entered terminal failure stage {stage}")
        time.sleep(interval_s)
    raise AssertionError(f"directory did not reach {target_stages} within {timeout_s}s (last={stage})")


def _wait_for_not_found(ctx, directory_id, timeout_s=1500, interval_s=20):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    last_stage = None
    while time.monotonic() < deadline:
        try:
            descs = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["ResponseMetadata"]["HTTPStatusCode"]
        if not descs:
            return "EmptyDescription", 200
        last_stage = descs[0]["Stage"]
        time.sleep(interval_s)
    raise AssertionError(f"directory never disappeared from DescribeDirectories (last stage={last_stage})")


# EC2 network teardown: a directory or other resource in this VPC deletes asynchronously, so its ENIs
# linger and DeleteSubnet/DeleteSecurityGroup/DeleteVpc fail with DependencyViolation until they go.
# Wait (bounded, shared by all of one check's network deletes) and retry, then raise naming the ENIs.
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
        enis = client.describe_network_interfaces(Filters=flt).get("NetworkInterfaces") or []
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
