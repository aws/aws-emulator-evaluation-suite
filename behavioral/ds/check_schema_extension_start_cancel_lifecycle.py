"""schema-extension-start-cancel-lifecycle."""
from __future__ import annotations

import secrets
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "schema-extension-start-cancel-lifecycle"
GROUP = "state-machine"
SERVICES = ["ds"]

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartSchemaExtension creates an entry visible in ListSchemaExtensions;
    CancelSchemaExtension transitions it to Cancelled state."""
    ds = ctx.client("ds")
    vpc_id, subnet_ids = _create_vpc_with_two_subnets(ctx)
    directory_id, domain_dn = _create_active_microsoft_ad(ctx, ds, vpc_id, subnet_ids)

    ldif = _build_test_ldif(domain_dn)
    schema_extension_id = ds.start_schema_extension(
        DirectoryId=directory_id,
        CreateSnapshotBeforeSchemaExtension=False,
        LdifContent=ldif,
        Description="sim2real behavioral test schema extension",
    )["SchemaExtensionId"]

    def _find(status_ok_terminal=False):
        entries = ds.list_schema_extensions(DirectoryId=directory_id)["SchemaExtensionsInfo"]
        for entry in entries:
            if entry["SchemaExtensionId"] == schema_extension_id:
                return entry
        return None

    entry = _poll_until(_find, lambda e: e is not None, timeout_s=120.0, interval_s=5.0)
    assert entry["SchemaExtensionStatus"] in (
        "Initializing",
        "CreatingSnapshot",
        "UpdatingSchema",
        "Replicating",
        "Completed",
    ), entry["SchemaExtensionStatus"]

    ds.cancel_schema_extension(DirectoryId=directory_id, SchemaExtensionId=schema_extension_id)

    final_entry = _poll_until(
        _find,
        lambda e: e is not None and e["SchemaExtensionStatus"] in ("Cancelled", "Completed", "Failed"),
        timeout_s=1800.0,
        interval_s=20.0,
    )
    assert final_entry["SchemaExtensionStatus"] == "Cancelled", final_entry["SchemaExtensionStatus"]


def _build_test_ldif(domain_dn: str) -> str:
    suffix = uuid.uuid4().hex[:10]
    attr_cn = f"sim2real-Test-Attr-{suffix}"
    ldap_display_name = f"sim2realTestAttr{suffix}"
    oid = f"1.2.840.113556.1.8000.2554.{int(suffix, 16) % 100000}.1.1.1"
    return (
        f"dn: CN={attr_cn},CN=Schema,CN=Configuration,{domain_dn}\n"
        "changetype: add\n"
        f"adminDescription: sim2real behavioral test attribute {suffix}\n"
        f"adminDisplayName: {attr_cn}\n"
        f"attributeID: {oid}\n"
        "attributeSyntax: 2.5.5.12\n"
        "isSingleValued: TRUE\n"
        f"ldapDisplayName: {ldap_display_name}\n"
        "oMSyntax: 64\n"
        f"name: {attr_cn}\n"
        "objectClass: attributeSchema\n"
    )


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DirectoryDoesNotExistException",
            "EntityDoesNotExistException",
        ):
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _ad_password() -> str:
    return "Sim2Real!" + secrets.token_hex(8) + "Aa1"


def _tag_spec(ctx, resource_type: str, kind: str):
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-ds-{kind}-")}],
    }


def _create_vpc_with_two_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.177.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc", "vpc")])["Vpc"]["VpcId"]

    def _cleanup_vpc():
        _gone_ok(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id), "InvalidVpcID.NotFound")

    ctx.on_cleanup(_cleanup_vpc)
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
    az_names = [az["ZoneName"] for az in azs if az.get("ZoneId") not in _DS_UNSUPPORTED_ZONE_IDS][:2]
    if len(az_names) < 2:
        raise AssertionError("region does not have 2 available AZs")

    subnet_ids = []
    for i, az in enumerate(az_names):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.177.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec(ctx, "subnet", "subnet")],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)

        def _cleanup_subnet(sid=subnet_id):
            _gone_ok(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid), "InvalidSubnetID.NotFound")

        ctx.on_cleanup(_cleanup_subnet)
    return vpc_id, subnet_ids


def _gone_ok(fn, not_found: str) -> None:
    """Teardown call: the resource being already gone (``not_found``) is fine, anything else raises.

    _delete_net itself retries DependencyViolation while the directory's ENIs leave."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != not_found:
            raise


def _create_active_microsoft_ad(ctx, ds, vpc_id, subnet_ids):
    domain_label = ctx.unique_name("sim2real-msad-")
    name = f"{domain_label}.example.com"
    domain_dn = ",".join(f"DC={part}" for part in name.split("."))
    directory_id = ds.create_microsoft_ad(
        Name=name,
        Password=_ad_password(),
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Edition="Standard",
    )["DirectoryId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ds.delete_directory(DirectoryId=directory_id)))

    stage = _poll_until(
        lambda: ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]["Stage"],
        lambda s: s in ("Active", "Failed"),
        timeout_s=5400.0,
        interval_s=30.0,
    )
    if stage != "Active":
        raise AssertionError(f"directory reached terminal stage {stage!r} instead of Active")
    return directory_id, domain_dn


# A resource deleted in this VPC keeps its AWS-managed ENIs for a while after its delete returns, so
# DeleteSubnet / DeleteSecurityGroup / DeleteVpc answer DependencyViolation until they go: the teardown
# retries inside one window shared by the check's network deletes and raises naming the ENIs left.
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
