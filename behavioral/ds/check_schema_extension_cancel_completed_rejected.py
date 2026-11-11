"""schema-extension-cancel-completed-rejected."""
from __future__ import annotations

import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "schema-extension-cancel-completed-rejected"
GROUP = "state-machine"
SERVICES = ["ds"]

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

# Unique to this check: a run deletes the directory it creates, so no other check may find it.
_MSAD_NAME = "sim2real-behav-msad-70cd95da.example.com"
_MSAD_PASSWORD = "Sim2Real-Check-Passw0rd1!"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelSchemaExtension on an extension that reached Completed fails with ClientException
    and leaves it Completed, while cancelling a fresh in-progress extension on the same directory
    succeeds and reaches Cancelled."""
    ds = ctx.client("ds")
    directory_id = _get_active_msad(ctx)
    domain_name = _MSAD_NAME
    dc = _domain_to_dc(domain_name)

    completed_id = _start_extension(ctx, directory_id, dc, "sim2RealDoneAttr")
    completed = _wait_extension_status(ctx, directory_id, completed_id, {"Completed"}, {"Failed", "Cancelled"})
    assert completed["SchemaExtensionStatus"] == "Completed", (
        f"expected extension {completed_id} to reach Completed, got {completed['SchemaExtensionStatus']!r}"
    )

    code = _error_code(lambda: ds.cancel_schema_extension(DirectoryId=directory_id, SchemaExtensionId=completed_id))
    assert code == "ClientException", (
        f"expected CancelSchemaExtension on completed extension {completed_id} to fail with "
        f"ClientException, got {code!r}"
    )

    # effect absent: the completed extension's status did not change because of the rejected cancel.
    still_completed = _extension_entry(ctx, directory_id, completed_id)
    assert still_completed["SchemaExtensionStatus"] == "Completed", (
        f"expected extension {completed_id} to remain Completed after the rejected cancel, "
        f"got {still_completed['SchemaExtensionStatus']!r}"
    )

    # positive control: cancelling a fresh, still in-progress extension succeeds.
    in_progress_id = _start_extension(ctx, directory_id, dc, "sim2RealLiveAttr")
    ctx.on_cleanup(lambda: _cancel_extension(ds, directory_id, in_progress_id))
    ds.cancel_schema_extension(DirectoryId=directory_id, SchemaExtensionId=in_progress_id)
    cancelled = _wait_extension_status(ctx, directory_id, in_progress_id, {"Cancelled"}, {"Completed", "Failed"})
    assert cancelled["SchemaExtensionStatus"] == "Cancelled", (
        f"expected extension {in_progress_id} to reach Cancelled after CancelSchemaExtension, "
        f"got {cancelled['SchemaExtensionStatus']!r}"
    )


def _error_code(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, because an
    over-permissive target accepting a call real AWS rejects is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _cancel_extension(ds, directory_id, extension_id) -> None:
    """Teardown: cancel the extension unless it is already finished or being cancelled; a directory
    already gone is done."""
    try:
        entries = ds.list_schema_extensions(DirectoryId=directory_id)["SchemaExtensionsInfo"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityDoesNotExistException":
            raise
        return
    status = next((e["SchemaExtensionStatus"] for e in entries if e["SchemaExtensionId"] == extension_id), None)
    if status in (None, "Completed", "Cancelled", "Failed", "CancelInProgress", "RollbackInProgress"):
        return
    ds.cancel_schema_extension(DirectoryId=directory_id, SchemaExtensionId=extension_id)


def _domain_to_dc(domain_name: str) -> str:
    return ",".join(f"DC={label}" for label in domain_name.split("."))


def _start_extension(ctx, directory_id, dc, attribute_name) -> str:
    """Start an extension that adds a new attributeSchema object, with a fresh OID, to the schema
    and then applies the schema update."""
    ds = ctx.client("ds")
    oid = f"1.2.840.113556.1.8000.2554.{secrets.randbelow(900000) + 100000}.1.1"
    ldif = (
        f"dn: CN={attribute_name},CN=Schema,CN=Configuration,{dc}\n"
        "changetype: add\n"
        "objectClass: attributeSchema\n"
        f"adminDisplayName: {attribute_name}\n"
        f"attributeId: {oid}\n"
        "attributeSyntax: 2.5.5.12\n"
        "omSyntax: 64\n"
        "isSingleValued: TRUE\n"
        f"lDAPDisplayName: {attribute_name}\n"
        f"name: {attribute_name}\n"
        "\n"
        "dn:\n"
        "changetype: modify\n"
        "replace: schemaUpdateNow\n"
        "schemaUpdateNow: 1\n"
        "-"
    )
    resp = ds.start_schema_extension(
        DirectoryId=directory_id,
        CreateSnapshotBeforeSchemaExtension=False,
        LdifContent=ldif,
        Description=ctx.unique_name("sim2real-ds-schemaext-"),
    )
    return resp["SchemaExtensionId"]


def _extension_entry(ctx, directory_id, extension_id):
    ds = ctx.client("ds")
    entries = ds.list_schema_extensions(DirectoryId=directory_id)["SchemaExtensionsInfo"]
    matches = [e for e in entries if e["SchemaExtensionId"] == extension_id]
    if not matches:
        raise AssertionError(f"extension {extension_id} vanished from ListSchemaExtensions")
    return matches[0]


def _wait_extension_status(ctx, directory_id, extension_id, terminal_ok, terminal_bad, timeout_s=900.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        entry = _extension_entry(ctx, directory_id, extension_id)
        last = entry["SchemaExtensionStatus"]
        if last in terminal_ok:
            return entry
        if last in terminal_bad:
            raise AssertionError(f"extension {extension_id} reached unexpected status {last}")
        time.sleep(interval_s)
    raise AssertionError(f"extension {extension_id} stuck at status={last} after {timeout_s}s")


def _default_vpc_two_azs(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("need subnets in at least 2 distinct AZs to create a test directory")
    azs = sorted(by_az)
    return vpc_id, [by_az[azs[0]], by_az[azs[1]]]


def _find_directory_by_name(ctx, name):
    ds = ctx.client("ds")
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = ds.describe_directories(**kwargs)
        for d in resp.get("DirectoryDescriptions", []):
            if d["Name"] == name:
                return d
        token = resp.get("NextToken")
        if not token:
            return None


def _get_active_msad(ctx, budget_s=2700.0, interval_s=2.0):
    """Look up (or create) this check's Managed Microsoft AD directory and wait until it is Active.
    Real creation takes 20-45 minutes. The name is unique to this check, so the directory is deleted
    at cleanup whether this call created it or found it."""
    ds = ctx.client("ds")
    found = _find_directory_by_name(ctx, _MSAD_NAME)
    if found is None:
        vpc_id, subnet_ids = _default_vpc_two_azs(ctx)
        try:
            directory_id = ds.create_microsoft_ad(
                Name=_MSAD_NAME,
                Password=_MSAD_PASSWORD,
                Edition="Standard",
                VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
            )["DirectoryId"]
        except ClientError as e:
            if e.response["Error"]["Code"] != "EntityAlreadyExistsException":
                raise
            found = _find_directory_by_name(ctx, _MSAD_NAME)
            if found is None:
                raise
            directory_id = found["DirectoryId"]
        ctx.on_cleanup(lambda: _delete_directory_and_wait(ds, directory_id))
    else:
        directory_id = found["DirectoryId"]
        # The name is unique to this check, so a directory found here is a leftover of an
        # earlier run of it, and this run removes it.
        ctx.on_cleanup(lambda: _delete_directory_and_wait(ds, directory_id))
        if found["Stage"] in ("Failed", "Inoperable"):
            raise AssertionError(
                f"directory {directory_id} is in terminal stage "
                f"{found['Stage']!r}; it needs manual cleanup before this check can run"
            )
        if found["Stage"] == "Active":
            return directory_id

    deadline = time.monotonic() + min(budget_s, ctx.time_left())
    stage = None
    while time.monotonic() < deadline:
        descs = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        stage = descs[0]["Stage"] if descs else None
        if stage == "Active":
            return directory_id
        if stage in ("Failed", "Inoperable"):
            raise AssertionError(f"directory {directory_id} reached {stage}")
        time.sleep(interval_s)
    raise AssertionError(
        f"directory {directory_id} still {stage!r} after {budget_s}s"
    )


def _delete_directory_and_wait(ds, directory_id, timeout_s=1800.0, interval_s=2.0):
    """Delete a directory and wait until it is gone, so its ENIs and security group leave the
    shared network. DeleteDirectory is retried while the directory is still being created or is
    still shared with another account."""

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
                except ClientError as share_err:
                    if share_err.response["Error"]["Code"] != "EntityDoesNotExistException":
                        raise
                    shared = []
                for share in shared:
                    try:
                        ds.unshare_directory(
                            DirectoryId=directory_id,
                            UnshareTarget={"Id": share["SharedAccountId"], "Type": "ACCOUNT"},
                        )
                    except ClientError as unshare_err:
                        if unshare_err.response["Error"]["Code"] not in (
                            "EntityDoesNotExistException", "DirectoryNotSharedException",
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
