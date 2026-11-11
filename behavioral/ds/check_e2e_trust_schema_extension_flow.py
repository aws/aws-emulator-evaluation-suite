"""e2e-trust-schema-extension-flow."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "e2e-trust-schema-extension-flow"
GROUP = "e2e"
SERVICES = ["ds"]

DIR_PASSWORD = "Sim2Real!Passw0rd123"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTrust to a domain with no reachable peer succeeds but the trust reaches TrustState Failed;
    a schema extension is observed in progress and reaches Cancelled after CancelSchemaExtension."""
    ds = ctx.client("ds")
    ec2 = ctx.client("ec2")
    directory_id, domain_name = _create_microsoft_ad(ctx, ds, ec2)
    _wait_for_directory_stage(ctx, directory_id, {"Active"}, timeout_s=3600, interval_s=20)

    trust_id = ds.create_trust(
        DirectoryId=directory_id,
        RemoteDomainName=f"peer.{ctx.unique_name('sim2realtrust')}.test",
        TrustPassword="Sim2Real!TrustPassw0rd789",
        TrustDirection="One-Way: Outgoing",
        TrustType="Forest",
    )["TrustId"]
    ctx.on_cleanup(lambda: _safe(lambda: ds.delete_trust(TrustId=trust_id)))

    trust_terminal_states = {"Created", "Failed", "VerifyFailed"}

    def _trust_state():
        trusts = ds.describe_trusts(DirectoryId=directory_id, TrustIds=[trust_id])["Trusts"]
        return trusts[0]["TrustState"] if trusts else None

    def _trust_reached_terminal():
        return _trust_state() in trust_terminal_states

    assert _poll_until(_trust_reached_terminal, timeout_s=600, interval_s=10), (
        f"TrustState never reached a terminal state after CreateTrust (last={_trust_state()})"
    )
    assert _trust_state() == "Failed", (
        "a one-way trust to a domain with no reachable peer must deterministically fail, "
        f"not land on {_trust_state()!r}"
    )

    dn = ",".join(f"DC={part}" for part in domain_name.split("."))
    ldif = (
        f"dn: CN=Sim2Real-Test-Attribute,CN=Schema,CN=Configuration,{dn}\n"
        "changetype: add\n"
        "adminDescription: Sim2Real behavioral fidelity test attribute\n"
        "adminDisplayName: Sim2Real-Test-Attribute\n"
        "attributeID: 1.2.840.113556.1.8000.2554.55432.1.1.1.1\n"
        "attributeSyntax: 2.5.5.12\n"
        "cn: Sim2Real-Test-Attribute\n"
        "instanceType: 4\n"
        "isSingleValued: TRUE\n"
        "ldapDisplayName: sim2RealTestAttribute\n"
        "name: Sim2Real-Test-Attribute\n"
        "objectClass: attributeSchema\n"
        "oMSyntax: 64\n"
    )
    schema_extension_id = ds.start_schema_extension(
        DirectoryId=directory_id,
        CreateSnapshotBeforeSchemaExtension=False,
        LdifContent=ldif,
        Description="sim2real-behav-schema-extension",
    )["SchemaExtensionId"]

    def _extension_status():
        entries = ds.list_schema_extensions(DirectoryId=directory_id)["SchemaExtensionsInfo"]
        match = next((e for e in entries if e["SchemaExtensionId"] == schema_extension_id), None)
        return match["SchemaExtensionStatus"] if match else None

    in_progress_states = {"Initializing", "CreatingSnapshot", "UpdatingSchema", "Replicating"}

    def _observed_in_progress():
        return _extension_status() in in_progress_states

    assert _poll_until(_observed_in_progress, timeout_s=180, interval_s=5), (
        f"schema extension never observed in an in-progress state (last={_extension_status()})"
    )

    ds.cancel_schema_extension(DirectoryId=directory_id, SchemaExtensionId=schema_extension_id)

    def _cancelled():
        return _extension_status() == "Cancelled"

    assert _poll_until(_cancelled, timeout_s=900, interval_s=15), (
        f"schema extension never reached Cancelled after CancelSchemaExtension (last={_extension_status()})"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DirectoryDoesNotExistException",
            "EntityDoesNotExistException",
        ):
            raise


def _poll_until(predicate, *, timeout_s: float, interval_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval_s)
    return predicate()


def _wait_for_directory_stage(ctx, directory_id, target_stages, *, timeout_s: float, interval_s: float):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    stage = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        stage = desc["Stage"]
        if stage in target_stages:
            return desc
        if stage == "Failed":
            raise AssertionError(f"directory {directory_id} reached Failed while waiting for {target_stages}")
        time.sleep(interval_s)
    raise AssertionError(f"directory {directory_id} did not reach {target_stages} within {timeout_s}s (last={stage})")


def _default_vpc_subnets(ec2, *, ctx):
    """The shared network and two of its subnets in distinct AZs, avoiding the 5-VPC quota.

    The VPC is not mutated, so concurrent checks sharing it cannot interfere."""
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    assert vpcs, (
        "the run has no shared network, and a Managed Microsoft AD requires a VPC with two "
        "subnets in distinct availability zones"
    )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
    ])["Subnets"]
    subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
    by_zone: dict = {}
    for subnet in sorted(subnets, key=lambda s: s["SubnetId"]):
        by_zone.setdefault(subnet["AvailabilityZone"], subnet["SubnetId"])
    zones = sorted(by_zone)
    assert len(zones) >= 2, (
        f"a directory is Multi-AZ by requirement and needs two available zones with a subnet in "
        f"each; the shared network {vpc_id!r} offers {by_zone!r}"
    )
    return vpc_id, [by_zone[z] for z in zones[:2]]


def _create_microsoft_ad(ctx, ds, ec2):
    vpc_id, subnet_ids = _default_vpc_subnets(ec2, ctx=ctx)
    domain_name = f"{ctx.unique_name('sim2realds')}.test"
    directory_id = ds.create_microsoft_ad(
        Name=domain_name,
        Password=DIR_PASSWORD,
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Edition="Standard",
        Tags=[{"Key": "sim2real", "Value": "behavioral"}, {"Key": "sim2real-check", "Value": CHECK}],
    )["DirectoryId"]
    # DeleteDirectory works from any non-terminal stage, so cleanup is registered right away.
    ctx.on_cleanup(lambda: _safe(lambda: _delete_directory_and_wait(ds, directory_id)))
    return directory_id, domain_name


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
                except ClientError:
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
