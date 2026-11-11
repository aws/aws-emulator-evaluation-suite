"""ds-data-access-must-be-enabled-before-the-data-plane-answers."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "ds-data-access-must-be-enabled-before-the-data-plane-answers"
GROUP = 'directory-data-rejected'
SERVICES = ['ds']
# Also calls ds-data (the Directory Service Data API, a separate signed endpoint) and ec2.

_PASSWORD = "Sim2Real#Pass99"
_CREATE_TERMINAL = {"Active", "Inoperable", "Impaired", "Failed", "Deleted"}

_GATE_MESSAGE = ("DS Data feature is not enabled on this directory. This feature must "
                 "first be enabled by calling the EnableDirectoryDataAccess API.")


def _refusal(fn, what: str) -> dict:
    """The refusal fn() raised, flattened; a success raises.
    The whole response is merged over Error because restJson1 puts the modelled Reason at top level.
    """
    try:
        result = fn()
    except ClientError as exc:
        return {**exc.response, **(exc.response.get("Error") or {})}
    raise AssertionError(
        f"{what} SUCCEEDED where real AWS refuses it; the response was {result!r}"
    )


def _fields(response: dict) -> dict:
    """A boto3 response without ResponseMetadata, so two reads can be compared."""
    return {k: v for k, v in response.items() if k != "ResponseMetadata"}


def _poll(fn, pred, *, timeout_s: float, interval_s: float = 20.0):
    """Poll fn() until pred(result) is true or the deadline passes. Returns the last result."""
    deadline = time.monotonic() + timeout_s
    while True:
        result = fn()
        if pred(result):
            return result
        if time.monotonic() >= deadline:
            return result
        time.sleep(interval_s)


def _describe(ds, directory_id: str):
    """The DirectoryDescription for directory_id, or None once it is gone."""
    try:
        found = ds.describe_directories(DirectoryIds=[directory_id])
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "EntityDoesNotExistException":
            return None
        raise
    descriptions = found.get("DirectoryDescriptions") or []
    return descriptions[0] if descriptions else None


def _pages(fn, key: str, **kwargs) -> list:
    """Every item under `key` across every page of a ds-data List*/Search* operation.
    ds-data declares no botocore paginators, so the NextToken loop is explicit."""
    items, token = [], None
    while True:
        page = fn(**({**kwargs, "NextToken": token} if token else kwargs))
        items.extend(page.get(key) or [])
        token = page.get("NextToken")
        if not token:
            return items


def _default_vpc_subnets(ec2, *, ctx) -> tuple:
    """The shared network and two of its subnets in distinct AZs -> (vpc_id, subnet_ids, cidr).
    A Managed Microsoft AD needs two subnets in distinct availability zones."""
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    assert vpcs, (
        "the run has no shared network, and a Managed Microsoft AD requires a VPC with two "
        "subnets in distinct availability zones"
    )
    vpc = vpcs[0]
    subnets = ec2.describe_subnets(Filters=[
        {"Name": "vpc-id", "Values": [vpc["VpcId"]]},
        {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
    ])["Subnets"]
    subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
    by_zone: dict = {}
    for subnet in sorted(subnets, key=lambda x: x["SubnetId"]):
        by_zone.setdefault(subnet["AvailabilityZone"], subnet["SubnetId"])
    zones = sorted(by_zone)
    assert len(zones) >= 2, (
        f"a directory is Multi-AZ by requirement and needs two available zones with a subnet in "
        f"each; the shared network {vpc['VpcId']!r} offers {by_zone!r}"
    )
    return vpc["VpcId"], [by_zone[z] for z in zones[:2]], vpc["CidrBlock"]


def _provision_directory(ctx, ds, ec2, *, enable_data_access: bool) -> tuple:
    """A Standard AWS Managed Microsoft AD, Active, in the shared network.
    -> (directory_id, fqdn, description, subnet_ids, vpc_id)"""
    vpc_id, subnet_ids, vpc_cidr = _default_vpc_subnets(ec2, ctx=ctx)
    name = ctx.unique_name("sim2real-behav-")
    fqdn = f"{name}.example.com"

    directory_id = ds.create_microsoft_ad(
        Name=fqdn, ShortName="SIM2REAL", Password=_PASSWORD, Edition="Standard",
        Description=f"sim2real behavioral {CHECK}",
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Tags=[{"Key": "sim2real", "Value": "behavioral"},
              {"Key": "sim2real-check", "Value": CHECK}],
    )["DirectoryId"]
    # Registered immediately: a Managed AD bills per hour until DeleteDirectory completes.
    ctx.on_cleanup(lambda: _delete_directory_and_wait(ds, directory_id))

    # A Managed AD create can take 40-55 minutes, so the deadline clears the slowest create.
    desc = _poll(
        lambda: _describe(ds, directory_id) or {},
        lambda d: d.get("Stage") in _CREATE_TERMINAL,
        timeout_s=3600.0,
        interval_s=20.0,
    )
    assert desc.get("Stage") == "Active", (
        f"the directory must reach Stage 'Active' before anything below is meaningful, got "
        f"{desc.get('Stage')!r} (StageReason={desc.get('StageReason')!r})"
    )
    assert (desc.get("VpcSettings") or {}).get("VpcId") == vpc_id, (
        f"the directory must have been placed in the VPC that was asked for, got "
        f"{desc.get('VpcSettings')!r} for {vpc_id!r} ({vpc_cidr})"
    )

    if enable_data_access:
        ds.enable_directory_data_access(DirectoryId=directory_id)
        ctx.on_cleanup(lambda: ds.disable_directory_data_access(DirectoryId=directory_id))
        status = _poll(
            lambda: ds.describe_directory_data_access(
                DirectoryId=directory_id).get("DataAccessStatus"),
            lambda s: s in ("Enabled", "Failed"),
            # Enabling typically takes seconds; 300s leaves wide headroom.
            timeout_s=300.0,
            interval_s=15.0,
        )
        assert status == "Enabled", (
            f"EnableDirectoryDataAccess must drive DataAccessStatus to 'Enabled' before the "
            f"ds-data endpoint will answer, it reached {status!r}"
        )

    return directory_id, fqdn, desc, subnet_ids, vpc_id


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """The Directory Service Data API refuses requests to an Active Managed AD with DATA_DISABLED
    until EnableDirectoryDataAccess is called; the refused CreateUser creates nothing, and the
    identical CreateUser then succeeds and DescribeUser reads the user back.
    """
    ds = ctx.client("ds")
    ec2 = ctx.client("ec2")
    directory_id, fqdn, _desc, _subnets, _vpc = _provision_directory(
        ctx, ds, ec2, enable_data_access=False)

    initial = ds.describe_directory_data_access(DirectoryId=directory_id)
    assert initial.get("DataAccessStatus") == "Disabled", (
        f"a freshly created Managed Microsoft AD must report DataAccessStatus 'Disabled' -- "
        f"nothing here has called EnableDirectoryDataAccess yet -- got {initial!r}"
    )

    dsdata = ctx.client("ds-data")
    sam = "sim2realGated"
    email = f"{sam}@{fqdn}"
    # Registered before the call that must fail, in case it is wrongly accepted.
    ctx.on_cleanup(lambda: dsdata.delete_user(DirectoryId=directory_id, SAMAccountName=sam))

    refused = _refusal(
        lambda: dsdata.create_user(
            DirectoryId=directory_id, SAMAccountName=sam, GivenName="Sim", Surname="Real",
            EmailAddress=email),
        "CreateUser against a directory whose data access has never been enabled",
    )
    assert refused.get("Code") == "AccessDeniedException", (
        f"ds-data must refuse a directory whose data access has never been enabled with "
        f"AccessDeniedException, got {refused!r}"
    )
    # AccessDeniedException is shared with IAM and directory-auth refusals; Reason and the
    # message pin this one to the data-access toggle.
    assert refused.get("Reason") == "DATA_DISABLED", (
        f"the refusal must name the DISABLED DATA PLANE as its reason, not an IAM or directory "
        f"authentication problem, got Reason={refused.get('Reason')!r} in {refused!r}"
    )
    assert refused.get("Message") == _GATE_MESSAGE, (
        f"the refusal must name the disabled feature and the API that enables it, got "
        f"{refused.get('Message')!r}"
    )

    # Reads are refused too, so "nothing was created" can only be checked after the toggle.
    refused_read = _refusal(
        lambda: dsdata.list_users(DirectoryId=directory_id),
        "ListUsers against a directory whose data access has never been enabled",
    )
    assert refused_read.get("Code") == "AccessDeniedException", (
        f"the refusal is directory-scoped, not operation-scoped: ListUsers must be refused with "
        f"the same AccessDeniedException, got {refused_read!r}"
    )
    assert refused_read.get("Message") == refused.get("Message"), (
        f"a read and a write against the same switched-off directory must be refused with the "
        f"IDENTICAL diagnostic -- the gate is on the directory, not on the operation: "
        f"{refused_read.get('Message')!r} != {refused.get('Message')!r}"
    )

    ds.enable_directory_data_access(DirectoryId=directory_id)
    ctx.on_cleanup(lambda: ds.disable_directory_data_access(DirectoryId=directory_id))
    status = _poll(
        lambda: ds.describe_directory_data_access(
            DirectoryId=directory_id).get("DataAccessStatus"),
        lambda s: s in ("Enabled", "Failed"),
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert status == "Enabled", (
        f"EnableDirectoryDataAccess must drive DataAccessStatus to 'Enabled', it reached "
        f"{status!r}"
    )

    before = {u.get("SAMAccountName") for u in _pages(
        dsdata.list_users, "Users", DirectoryId=directory_id)}
    assert sam not in before, (
        f"the refused CreateUser had created a directory object after all: {sam!r} is in the "
        f"paginated ListUsers inventory of {len(before)} users, {sorted(before)!r}"
    )

    created = dsdata.create_user(
        DirectoryId=directory_id, SAMAccountName=sam, GivenName="Sim", Surname="Real",
        EmailAddress=email)
    assert created.get("SAMAccountName") == sam, (
        f"positive control failed: the identical CreateUser must succeed once data access is "
        f"Enabled, got {created!r}"
    )
    control = dsdata.describe_user(DirectoryId=directory_id, SAMAccountName=sam)
    assert control.get("SAMAccountName") == sam, (
        f"positive control failed: DescribeUser must return the user the identical request just "
        f"created, got {control!r}"
    )
    assert control.get("EmailAddress") == email, (
        f"positive control failed: the attributes of the accepted request must have reached "
        f"Active Directory, expected EmailAddress {email!r}, got {control!r}"
    )
    after = {u.get("SAMAccountName") for u in _pages(
        dsdata.list_users, "Users", DirectoryId=directory_id)}
    assert sam in after, (
        f"positive control failed: {sam!r} must appear in the paginated ListUsers inventory after "
        f"the accepted create, got {sorted(after)!r}"
    )


def _delete_directory_and_wait(ds, directory_id, timeout_s=1500.0, interval_s=30.0):
    """Delete a directory and wait until it is gone, so its ENIs and security group leave the
    shared network. DeleteDirectory is retried while the directory is still being created or is
    still shared with another account."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ds.delete_directory(DirectoryId=directory_id)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "EntityDoesNotExistException":
                return
            if "shared" in e.response["Error"].get("Message", "").lower():
                try:
                    shared = ds.describe_shared_directories(OwnerDirectoryId=directory_id)["SharedDirectories"]
                except ClientError as exc:
                    if exc.response["Error"]["Code"] not in (
                        "DirectoryDoesNotExistException",
                        "EntityDoesNotExistException",
                    ):
                        raise
                    shared = []
                for share in shared:
                    try:
                        ds.unshare_directory(
                            DirectoryId=directory_id,
                            UnshareTarget={"Id": share["SharedAccountId"], "Type": "ACCOUNT"},
                        )
                    except ClientError as exc:
                        if exc.response["Error"]["Code"] not in (
                            "DirectoryDoesNotExistException",
                            "EntityDoesNotExistException",
                        ):
                            raise
            elif code not in ("ClientException", "InvalidParameterException"):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    while True:
        try:
            found = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "EntityDoesNotExistException":
                return
            raise
        if not found or found[0].get("Stage") == "Deleted":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"directory {directory_id} still exists {timeout_s:.0f}s after DeleteDirectory")
        time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
