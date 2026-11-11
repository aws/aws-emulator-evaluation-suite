"""ds-trust-to-an-unresolvable-remote-domain-fails-and-leaves-no-trust."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "ds-trust-to-an-unresolvable-remote-domain-fails-and-leaves-no-trust"
GROUP = 'trust-rejected'
SERVICES = ['ds']
# Also calls ec2, only to find the VPC substrate a directory requires.

_PASSWORD = "Sim2Real#Pass99"
_CREATE_TERMINAL = {"Active", "Inoperable", "Impaired", "Failed", "Deleted"}

# RFC 2606 reserves .invalid so this domain can never resolve, in this account or any other.
_REMOTE_DOMAIN = "sim2real-nonexistent.invalid"
_TRUST_PASSWORD = "Sim2Real#Trust99"
# RFC 5737 documentation range: a conditional forwarder address that routes nowhere.
_TEST_NET_ADDR = "192.0.2.53"
# Every state a trust may settle in, so the poll stops wherever it lands; an unresolvable remote
# domain goes Creating -> Failed in about 20s.
_TRUST_TERMINAL = {"Verified", "Failed", "VerifyFailed", "Deleted"}


def _refusal(fn, what: str) -> dict:
    """The refusal fn() raised, flattened, with top-level modelled members merged over ``Error``.

    An unexpected success raises.
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
    """Every item under `key` across every page, following NextToken explicitly."""
    items, token = [], None
    while True:
        page = fn(**({**kwargs, "NextToken": token} if token else kwargs))
        items.extend(page.get(key) or [])
        token = page.get("NextToken")
        if not token:
            return items


def _default_vpc_subnets(ec2, *, ctx) -> tuple:
    """The shared network VPC and two of its subnets in distinct AZs, derived from what the
    account offers. -> (vpc_id, [subnet_id, subnet_id], cidr_block)
    """
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
    """A Standard AWS Managed Microsoft AD, Active, with its delete registered at once (it bills
    hourly). -> (directory_id, fqdn, description, subnet_ids, vpc_id)
    """
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
    ctx.on_cleanup(lambda: ds.delete_directory(DirectoryId=directory_id))

    # A Managed AD create can stay 'Creating' past 3300s with several in flight, so the deadline
    # allows for the slow case rather than the typical one.
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
            # EnableDirectoryDataAccess typically reaches 'Enabled' in about 15s.
            timeout_s=300.0,
            interval_s=15.0,
        )
        assert status == "Enabled", (
            f"EnableDirectoryDataAccess must drive DataAccessStatus to 'Enabled' before the "
            f"ds-data endpoint will answer, it reached {status!r}"
        )

    return directory_id, fqdn, desc, subnet_ids, vpc_id


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """CreateTrust to an unresolvable remote domain is accepted, then fails asynchronously (Creating, then
    Failed with a TrustStateReason, never Verified); after DeleteTrust, DescribeTrusts by id and a second
    delete fail with "Trust: <id> does not exist", and the directory stays Active."""
    ds = ctx.client("ds")
    ec2 = ctx.client("ec2")
    directory_id, _fqdn, _desc, _subnets, _vpc = _provision_directory(
        ctx, ds, ec2, enable_data_access=False)

    before = _pages(ds.describe_trusts, "Trusts", DirectoryId=directory_id)
    assert before == [], (
        f"the check needs a directory with no trusts to start from, got {before!r}"
    )

    # The only defect is the remote domain in the reserved .invalid TLD.
    created = ds.create_trust(
        DirectoryId=directory_id, RemoteDomainName=_REMOTE_DOMAIN,
        TrustPassword=_TRUST_PASSWORD, TrustDirection="One-Way: Outgoing", TrustType="Forest",
        ConditionalForwarderIpAddrs=[_TEST_NET_ADDR],
    )
    trust_id = created.get("TrustId") or ""
    # Registered immediately: real AWS ACCEPTS this call, so the record exists from here on and a
    # failing assertion below must not leak it.
    ctx.on_cleanup(lambda: _delete_trust_if_present(ds, trust_id))
    assert trust_id.startswith("t-"), (
        f"CreateTrust must mint a t- TrustId even for a domain that cannot resolve, got {created!r}"
    )

    observed = []

    def _probe():
        rows = [t for t in _pages(ds.describe_trusts, "Trusts", DirectoryId=directory_id)
                if t.get("TrustId") == trust_id]
        row = rows[0] if rows else {}
        state = row.get("TrustState")
        if state and (not observed or observed[-1] != state):
            observed.append(state)
        return row

    trust = _poll(_probe, lambda t: t.get("TrustState") in _TRUST_TERMINAL,
                  timeout_s=600.0,
                  interval_s=10.0)
    assert trust.get("TrustState") == "Failed", (
        f"a trust to a domain that cannot resolve must reach the terminal state 'Failed', it "
        f"reached {trust.get('TrustState')!r} (reason {trust.get('TrustStateReason')!r}); states "
        f"observed: {observed!r}"
    )
    assert "Verified" not in observed, (
        f"a trust whose remote domain does not exist must never be reported Verified, states "
        f"observed: {observed!r}"
    )
    assert observed[0] == "Creating", (
        f"the trust must be observed being created before it fails -- the failure is the result of "
        f"a handshake, not a synchronous validation: {observed!r}"
    )
    assert trust.get("TrustStateReason"), (
        f"a failed trust must carry a diagnostic in TrustStateReason, got {trust!r}"
    )

    # The request's fields survive, so the failure is the handshake's, not a dropped request.
    assert trust.get("RemoteDomainName") == _REMOTE_DOMAIN, f"{trust!r}"
    assert trust.get("TrustDirection") == "One-Way: Outgoing", f"{trust!r}"
    assert trust.get("TrustType") == "Forest", f"{trust!r}"
    assert trust.get("SelectiveAuth") == "Disabled", (
        f"nothing here enabled selective authentication, so it must report Disabled, got {trust!r}"
    )
    assert "TrustPassword" not in trust and _TRUST_PASSWORD not in str(trust), (
        f"the trust password must never be returned: {trust!r}"
    )
    assert trust.get("StateLastUpdatedDateTime") >= trust.get("CreatedDateTime"), (
        f"the state cannot have last changed before the trust was created: {trust!r}"
    )

    deleted = ds.delete_trust(TrustId=trust_id)
    assert deleted.get("TrustId") == trust_id, (
        f"DeleteTrust must echo the trust it removed, got {deleted!r}"
    )
    remaining = _poll(
        lambda: _pages(ds.describe_trusts, "Trusts", DirectoryId=directory_id),
        lambda rows: not [t for t in rows if t.get("TrustId") == trust_id],
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert [t for t in remaining if t.get("TrustId") == trust_id] == [], (
        f"{trust_id!r} survived DeleteTrust in the paginated DescribeTrusts inventory: "
        f"{remaining!r}"
    )

    # DescribeTrusts by TrustIds without a DirectoryId is rejected ("Directory ID must be
    # specified") although the model marks it optional, so DirectoryId is passed.
    by_id = _refusal(
        lambda: ds.describe_trusts(DirectoryId=directory_id, TrustIds=[trust_id]),
        "DescribeTrusts(DirectoryId=..., TrustIds=[deleted])",
    )
    assert by_id.get("Code") == "EntityDoesNotExistException", (
        f"a by-id DescribeTrusts on the deleted trust must fail with EntityDoesNotExistException, "
        f"got {by_id!r}"
    )
    assert by_id.get("Message") == (
        f"Trust: {trust_id} does not exist : RequestId: {by_id['ResponseMetadata']['RequestId']}"
    ), f"unexpected EntityDoesNotExistException message: {by_id.get('Message')!r}"
    redelete = _refusal(lambda: ds.delete_trust(TrustId=trust_id), "DeleteTrust(already-deleted)")
    assert redelete.get("Code") == "EntityDoesNotExistException", (
        f"deleting an already-deleted trust must also fail with EntityDoesNotExistException, got "
        f"{redelete!r}"
    )
    assert redelete.get("Message") == (
        f"Trust: {trust_id} does not exist : RequestId: {redelete['ResponseMetadata']['RequestId']}"
    ), f"unexpected EntityDoesNotExistException message: {redelete.get('Message')!r}"

    # Positive control: the failed handshake damaged nothing.
    control = _describe(ds, directory_id) or {}
    assert control.get("Stage") == "Active", (
        f"positive control failed: the directory must still be Active after a failed trust "
        f"handshake, got {control.get('Stage')!r} (StageReason={control.get('StageReason')!r})"
    )
    assert control.get("DnsIpAddrs"), (
        f"positive control failed: the directory must still report its domain controllers, got "
        f"{control!r}"
    )


def _delete_trust_if_present(ds, trust_id):
    """The check deletes the trust itself; teardown only removes one that is still there."""
    try:
        ds.delete_trust(TrustId=trust_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "EntityDoesNotExistException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
