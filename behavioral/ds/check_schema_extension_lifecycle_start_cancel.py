"""schema-extension-lifecycle-start-cancel."""
from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "schema-extension-lifecycle-start-cancel"
GROUP = "state-machine"
SERVICES = ["ds"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartSchemaExtension on a Managed Microsoft AD directory creates an entry
    tracked via ListSchemaExtensions, and cancelling it early with
    CancelSchemaExtension drives its SchemaExtensionStatus to Cancelled."""
    ds = ctx.client("ds")
    domain_name = f"{ctx.unique_name('sim2realds')}.test"
    directory_id = _create_microsoft_ad(ctx, domain_name)
    ctx.on_cleanup(lambda: _cleanup_delete_directory(ctx, directory_id))
    desc = _wait_for_directory_stage(ctx, ds, directory_id, {"Active", "Failed"}, timeout_s=2700)
    assert desc["Stage"] == "Active"

    dc_parts = ",".join(f"DC={p}" for p in domain_name.split("."))
    attr_oid_suffix = random.randint(100000, 999999)
    ldif = (
        f"dn: CN=sim2RealTestAttr,CN=Schema,CN=Configuration,{dc_parts}\n"
        "changetype: add\n"
        "objectClass: attributeSchema\n"
        "adminDescription: sim2real behavioral fidelity test attribute\n"
        "adminDisplayName: sim2RealTestAttr\n"
        f"attributeId: 1.2.840.113556.1.8000.2554.{attr_oid_suffix}.1.1\n"
        "attributeSyntax: 2.5.5.12\n"
        "omSyntax: 64\n"
        "isSingleValued: TRUE\n"
        "lDAPDisplayName: sim2RealTestAttr\n"
        "name: sim2RealTestAttr\n"
        "-\n"
    )

    schema_extension_id = ds.start_schema_extension(
        DirectoryId=directory_id,
        CreateSnapshotBeforeSchemaExtension=False,
        LdifContent=ldif,
        Description="sim2real behavioral fidelity check",
    )["SchemaExtensionId"]

    def _cleanup_extension():
        try:
            ds.cancel_schema_extension(DirectoryId=directory_id, SchemaExtensionId=schema_extension_id)
        except ClientError as e:
            # The check cancels the extension itself; a second cancel is refused once the
            # process has moved on, and deleting the directory removes the extension anyway.
            if e.response["Error"]["Code"] == "ClientException" and "cannot cancel" in e.response["Error"].get("Message", ""):
                return
            if e.response["Error"]["Code"] != "EntityDoesNotExistException":
                raise

    ctx.on_cleanup(_cleanup_extension)

    ds.cancel_schema_extension(DirectoryId=directory_id, SchemaExtensionId=schema_extension_id)

    status = _wait_for_extension_status(ctx, ds, directory_id, schema_extension_id, {"Cancelled", "Completed"}, timeout_s=1800)
    assert status == "Cancelled", f"expected the extension to reach Cancelled, got {status!r}"


# ===== helpers =====

def _default_vpc_subnet_pairs(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network in the region to host the directory's network interfaces")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("shared network lacks subnets in >=2 availability zones, required by CreateMicrosoftAD")
    subnet_ids = list(by_az.values())
    return vpc_id, [(subnet_ids[i], subnet_ids[j]) for i in range(len(subnet_ids)) for j in range(i + 1, len(subnet_ids))]


def _create_microsoft_ad(ctx, domain_name: str) -> str:
    ds = ctx.client("ds")
    vpc_id, pairs = _default_vpc_subnet_pairs(ctx)
    last_error = None
    for pair in pairs:
        try:
            resp = ds.create_microsoft_ad(
                Name=domain_name,
                Password="Sim2Real-Test-Passw0rd!",
                VpcSettings={"VpcId": vpc_id, "SubnetIds": list(pair)},
                Edition="Standard",
            )
            return resp["DirectoryId"]
        except ClientError as e:
            # Directory Service does not support every AZ in a region ("Failed to locate
            # Availability Zone ... capacity constrained"); try the account's other AZ pairs
            # before giving up, since the default VPC usually has more than two AZs.
            if e.response["Error"]["Code"] != "ClientException" or "Availability Zone" not in str(e):
                raise
            last_error = e
    raise AssertionError(f"CreateMicrosoftAD rejected every default-VPC AZ pair: {last_error}")


def _cleanup_delete_directory(ctx, directory_id: str) -> None:
    ds = ctx.client("ds")
    try:
        ds.delete_directory(DirectoryId=directory_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "EntityDoesNotExistException":
            raise


def _wait_for_directory_stage(ctx, ds, directory_id: str, targets: set[str], timeout_s: float = 2700.0, interval_s: float = 30.0):
    deadline = time.monotonic() + timeout_s
    last_stage = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        last_stage = desc["Stage"]
        if last_stage in targets:
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"directory {directory_id} stuck at stage {last_stage!r} after {timeout_s}s")


def _wait_for_extension_status(ctx, ds, directory_id: str, schema_extension_id: str, targets: set[str], timeout_s: float = 1800.0, interval_s: float = 20.0):
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        infos = ds.list_schema_extensions(DirectoryId=directory_id)["SchemaExtensionsInfo"]
        match = next((i for i in infos if i["SchemaExtensionId"] == schema_extension_id), None)
        if match is not None:
            last_status = match["SchemaExtensionStatus"]
            if last_status in targets:
                return last_status
        time.sleep(interval_s)
    raise AssertionError(f"schema extension {schema_extension_id} stuck at status {last_status!r} after {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
