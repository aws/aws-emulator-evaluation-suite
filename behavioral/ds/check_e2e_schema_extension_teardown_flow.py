"""e2e-schema-extension-teardown-flow."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "e2e-schema-extension-teardown-flow"
GROUP = "e2e"
SERVICES = ["ds"]

_PASSWORD = "Sim2Real!2024Aa"

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}
#: The directory teardown's own bound, inside the ds suite's 1800 s cleanup budget; the network
#: teardown runs after it in the same budget.
_DIR_TEARDOWN_S = 1080.0

# The classic "Shoe-Size" custom-attribute example used throughout Microsoft's and AWS's
# own schema-extension tutorials; the OID is a private-arc example value, safe to reuse
# because each StartSchemaExtension call targets a fresh, single-use directory's own schema.
_ATTRIBUTE_OID = "1.2.840.113556.1.8000.750.65654.2.1"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartSchemaExtension on a Standard Managed Microsoft AD directory reaches a terminal state,
    and DeleteDirectory removes the schema extension's record along with the directory."""
    # Per-run state: the teardown deadlines, started by the first teardown that asks for each.
    run_state: dict = {}
    vpc_id, subnet_ids = _create_vpc_and_subnets(ctx, run_state)
    ds = ctx.client("ds")
    domain_name = f"{ctx.unique_name('sim2real-dsschema-')}.example.com"
    directory_id = ds.create_microsoft_ad(
        Name=domain_name,
        Password=_PASSWORD,
        Edition="Standard",
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["DirectoryId"]
    ctx.on_cleanup(lambda: _delete_directory_teardown(ctx, directory_id))

    stage = _wait_directory_stage(ctx, directory_id, {"Active", "Failed"}, timeout_s=2700.0)
    assert stage == "Active", f"directory did not reach Active (got {stage})"

    ldif = _ldif_content(domain_name)
    schema_extension_id = ds.start_schema_extension(
        DirectoryId=directory_id,
        CreateSnapshotBeforeSchemaExtension=False,
        LdifContent=ldif,
        Description="sim2real-behavioral-schema-extension",
    )["SchemaExtensionId"]

    terminal_status = _poll_until(
        lambda: _schema_extension_status(ds, directory_id, schema_extension_id),
        lambda s: s in {"Completed", "Cancelled", "Failed"},
        timeout_s=3600.0,
        interval_s=30.0,
    )
    assert terminal_status == "Completed", (
        f"schema extension {schema_extension_id} ended in {terminal_status!r}, expected Completed"
    )

    ds.delete_directory(DirectoryId=directory_id)
    deleted = _poll_until(
        lambda: _directory_gone(ds, directory_id),
        lambda gone: gone is True,
        timeout_s=1500.0,
        interval_s=15.0,
    )
    assert deleted is True, f"directory {directory_id} was not removed within the timeout"

    remaining = ds.list_schema_extensions(DirectoryId=directory_id)["SchemaExtensionsInfo"]
    assert remaining == [], f"expected no schema extension records for the deleted directory, got {remaining!r}"


def _ldif_content(domain_name: str) -> str:
    dc = ",".join(f"DC={part}" for part in domain_name.split("."))
    return (
        f"dn: CN=Shoe-Size,CN=Schema,CN=Configuration,{dc}\n"
        "changetype: add\n"
        "adminDescription: sim2real behavioral check attribute\n"
        "adminDisplayName: Shoe-Size\n"
        f"attributeId: {_ATTRIBUTE_OID}\n"
        "attributeSyntax: 2.5.5.4\n"
        "cn: Shoe-Size\n"
        "isSingleValued: TRUE\n"
        "ldapDisplayName: shoeSize\n"
        "name: Shoe-Size\n"
        "objectClass: attributeSchema\n"
        "oMSyntax: 20\n"
        "\n"
        # The schema cache is refreshed after each change, so the User class can name the new
        # attribute (by its lDAPDisplayName).
        "dn:\n"
        "changetype: modify\n"
        "replace: schemaUpdateNow\n"
        "schemaUpdateNow: 1\n"
        "-\n"
        "\n"
        f"dn: CN=User,CN=Schema,CN=Configuration,{dc}\n"
        "changetype: modify\n"
        "add: mayContain\n"
        "mayContain: shoeSize\n"
        "-\n"
        "\n"
        "dn:\n"
        "changetype: modify\n"
        "replace: schemaUpdateNow\n"
        "schemaUpdateNow: 1\n"
        "-"
    )


def _schema_extension_status(ds, directory_id: str, schema_extension_id: str) -> str:
    resp = ds.list_schema_extensions(DirectoryId=directory_id)
    for entry in resp["SchemaExtensionsInfo"]:
        if entry["SchemaExtensionId"] == schema_extension_id:
            return entry["SchemaExtensionStatus"]
    return "Absent"


def _directory_gone(ds, directory_id: str) -> bool:
    from botocore.exceptions import ClientError

    try:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "EntityDoesNotExistException":
            return True
        raise
    return not desc or desc[0]["Stage"] == "Deleted"


def _create_vpc_and_subnets(ctx, run_state: dict) -> tuple[str, list[str]]:
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.74.0.0/16",
        TagSpecifications=[{
            "ResourceType": "vpc",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-dsschema-vpc-")}],
        }],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _gone_ok(lambda: _delete_net(ec2, run_state, "delete_vpc", VpcId=vpc_id)))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    azs = [
        a["ZoneName"]
        for a in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
        if a.get("ZoneId") not in _DS_UNSUPPORTED_ZONE_IDS
    ][:2]
    if len(azs) < 2:
        raise AssertionError("region does not have 2+ available AZs required by DS")
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.74.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{
                "ResourceType": "subnet",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-dsschema-subnet-")}],
            }],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)
        ctx.on_cleanup(
            lambda subnet_id=subnet_id: _gone_ok(
                lambda: _delete_net(ec2, run_state, "delete_subnet", SubnetId=subnet_id))
        )
    return vpc_id, subnet_ids


def _gone_ok(fn) -> None:
    """Teardown call: a VPC or subnet that is already gone is fine, anything else raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound"):
            raise


def _wait_directory_stage(ctx, directory_id: str, terminal_stages: set[str], timeout_s: float) -> str:
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    stage = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        if desc:
            stage = desc[0]["Stage"]
            if stage in terminal_stages:
                return stage
        time.sleep(2.0)
    raise AssertionError(f"directory {directory_id} did not reach {terminal_stages} in {timeout_s}s (last={stage})")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    return value


def _delete_directory_teardown(ctx, directory_id: str) -> None:
    """Teardown: once the directory has left Creating, delete it and wait until it is gone.

    Already gone (EntityDoesNotExistException) is fine; every other failure raises."""
    from botocore.exceptions import ClientError

    ds = ctx.client("ds")
    deadline = time.monotonic() + _DIR_TEARDOWN_S
    if _directory_gone(ds, directory_id):
        return
    _wait_directory_stage(ctx, directory_id, {"Active", "Failed", "Deleted"}, timeout_s=_DIR_TEARDOWN_S)
    try:
        ds.delete_directory(DirectoryId=directory_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "EntityDoesNotExistException":
            raise
    while not _directory_gone(ds, directory_id):
        if time.monotonic() >= deadline:
            raise AssertionError(f"directory {directory_id} still present {_DIR_TEARDOWN_S:.0f}s after DeleteDirectory")
        time.sleep(2.0)


# A resource deleted in this VPC keeps its AWS-managed ENIs for a while after its delete returns, so
# DeleteSubnet / DeleteSecurityGroup / DeleteVpc answer DependencyViolation until they go: the teardown
# retries inside one window shared by the check's network deletes and raises naming the ENIs left.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}


def _delete_net(client, run_state: dict, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    deadline = run_state.setdefault("net", _time.monotonic() + _NET_TEARDOWN_S)
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
