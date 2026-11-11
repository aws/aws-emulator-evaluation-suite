"""state-machine-schema-extension-start-cancel-status."""
from __future__ import annotations

import time
import zlib

from behavioral_harness import tags
from botocore.exceptions import ClientError

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "state-machine-schema-extension-start-cancel-status"
GROUP = "state-machine"
SERVICES = ["ds"]

_PASSWORD = "Sim2Real!Test2024"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartSchemaExtension enters an in-progress state (Initializing/CreatingSnapshot/
    UpdatingSchema/Replicating) and CancelSchemaExtension transitions it to Cancelled as
    reflected by ListSchemaExtensions, rather than leaving it stuck mid-flight."""
    ds = ctx.client("ds")
    directory_id, domain = _create_microsoft_ad(ctx)

    ldif = _build_add_attribute_ldif(domain, ctx.unique_name("sim2realAttr").replace("-", ""))
    extension_id = ds.start_schema_extension(
        DirectoryId=directory_id,
        CreateSnapshotBeforeSchemaExtension=False,
        LdifContent=ldif,
        Description="sim2real schema extension cancel test",
    )["SchemaExtensionId"]

    extension_cancelled = {"value": False}

    def _cleanup():
        if extension_cancelled["value"]:
            return
        try:
            ds.cancel_schema_extension(DirectoryId=directory_id, SchemaExtensionId=extension_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "DirectoryDoesNotExistException",
                "EntityDoesNotExistException",
            ):
                raise

    ctx.on_cleanup(_cleanup)

    initial_status = _find_extension_status(ctx, directory_id, extension_id)
    assert initial_status in (
        "Initializing",
        "CreatingSnapshot",
        "UpdatingSchema",
        "Replicating",
    ), f"unexpected initial in-progress status: {initial_status}"

    ds.cancel_schema_extension(DirectoryId=directory_id, SchemaExtensionId=extension_id)
    extension_cancelled["value"] = True

    final_status = _wait_for_extension_status(ctx, directory_id, extension_id, {"Cancelled"}, timeout_s=900)
    assert final_status == "Cancelled", f"unexpected final status: {final_status}"


def _pick_vpc_and_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    for vpc in vpcs:
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
        ).get("Subnets", [])
        subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
        by_az: dict[str, str] = {}
        for sn in subnets:
            by_az.setdefault(sn["AvailabilityZone"], sn["SubnetId"])
        if len(by_az) >= 2:
            return vpc["VpcId"], list(by_az.values())
    raise AssertionError("no VPC with subnets in >=2 availability zones to provision a DS directory")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_directory_stage(ctx, directory_id, target_stages, timeout_s=3600, interval_s=2):
    ds = ctx.client("ds")
    timeout_s = _budget_s(ctx, timeout_s)
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
    if _budget_spent(ctx):
        raise TimeoutError(f"directory {directory_id} reaching {target_stages}: the run budget ended first; not graded")
    raise AssertionError(f"directory did not reach {target_stages} within {timeout_s}s (last={stage})")


def _create_microsoft_ad(ctx, name_prefix="sim2realmsad"):
    import itertools

    ds = ctx.client("ds")
    vpc_id, subnet_ids = _pick_vpc_and_subnets(ctx)
    name = f"{ctx.unique_name(name_prefix)}.test"

    last_error = None
    directory_id = None
    for pair in itertools.combinations(subnet_ids, 2):
        try:
            directory_id = ds.create_microsoft_ad(
                Name=name,
                Password=_PASSWORD,
                VpcSettings={"VpcId": vpc_id, "SubnetIds": list(pair)},
                Edition="Standard",
            )["DirectoryId"]
            break
        except ClientError as e:
            # A specific AZ can be capacity-constrained for CreateMicrosoftAD independent of
            # the account's other quotas; try the other AZ pairs before giving up.
            if e.response["Error"]["Code"] != "ClientException" or "Availability Zone" not in str(e):
                raise
            last_error = e
    if directory_id is None:
        raise AssertionError(f"CreateMicrosoftAD rejected every available AZ pair: {last_error}")

    def _cleanup():
        try:
            ds.delete_directory(DirectoryId=directory_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "DirectoryDoesNotExistException",
                "EntityDoesNotExistException",
            ):
                raise

    ctx.on_cleanup(_cleanup)
    _wait_directory_stage(ctx, directory_id, {"Active"})
    return directory_id, name


def _build_add_attribute_ldif(domain_fqdn: str, attr_name: str) -> str:
    dc_parts = ",".join(f"DC={part}" for part in domain_fqdn.split("."))
    schema_dn = f"CN=Schema,CN=Configuration,{dc_parts}"
    oid_suffix = zlib.crc32(attr_name.encode()) % 100000
    return (
        f"dn: CN={attr_name},{schema_dn}\n"
        "changetype: add\n"
        f"adminDescription: {attr_name}\n"
        f"adminDisplayName: {attr_name}\n"
        f"attributeID: 1.2.840.113556.1.8000.2554.{oid_suffix}.1.1\n"
        "attributeSyntax: 2.5.5.12\n"
        "isSingleValued: TRUE\n"
        f"ldapDisplayName: {attr_name}\n"
        f"name: {attr_name}\n"
        "objectClass: attributeSchema\n"
        "\n"
        "dn:\n"
        "changetype: modify\n"
        "add: schemaUpdateNow\n"
        "schemaUpdateNow: 1\n"
        "-\n"
    )


def _find_extension_status(ctx, directory_id, extension_id):
    ds = ctx.client("ds")
    extensions = ds.list_schema_extensions(DirectoryId=directory_id)["SchemaExtensionsInfo"]
    for ext in extensions:
        if ext["SchemaExtensionId"] == extension_id:
            return ext["SchemaExtensionStatus"]
    raise AssertionError(f"schema extension {extension_id} not found in ListSchemaExtensions")


def _wait_for_extension_status(ctx, directory_id, extension_id, target_statuses, timeout_s=900, interval_s=2):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = _find_extension_status(ctx, directory_id, extension_id)
        if status in target_statuses:
            return status
        if status == "Failed":
            raise AssertionError("schema extension failed instead of being cancelled")
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"schema extension {extension_id} reaching {target_statuses}: the run budget ended first; not graded")
    raise AssertionError(f"schema extension never reached {target_statuses} (last={status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
