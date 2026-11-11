"""create-trust-duplicate-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-trust-duplicate-rejected"
GROUP = "error-semantics"
SERVICES = ["ds"]

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateTrust to the same remote domain from one AWS Managed Microsoft AD directory is
    rejected with EntityAlreadyExistsException and AWS's trust-exists message and creates no second
    trust, while a trust to a different remote domain still succeeds."""
    ds = ctx.client("ds")
    directory_id, _vpc_id, _subnet_ids = _create_active_microsoft_ad(ctx)
    remote_domain = "sim2real-trust.example.test"

    # Positive control: creating the first trust to this remote domain succeeds.
    trust_id = ds.create_trust(
        DirectoryId=directory_id,
        RemoteDomainName=remote_domain,
        TrustPassword="Sim2RealTrustPassw0rd!",
        TrustDirection="One-Way: Outgoing",
    )["TrustId"]
    ctx.on_cleanup(lambda: _best_effort_delete_trust(ds, trust_id))

    before = _trusts_for_domain(ds, directory_id, remote_domain)
    assert len(before) == 1 and before[0]["TrustId"] == trust_id, (
        f"expected exactly 1 trust ({trust_id}) for {remote_domain}, found {before!r}"
    )

    # Negative: a second trust to the same remote domain from the same directory is
    # rejected. An unexpected success raises rather than reading as a code mismatch.
    code, message, request_id = _error(
        lambda: ds.create_trust(
            DirectoryId=directory_id,
            RemoteDomainName=remote_domain,
            TrustPassword="AnotherPassw0rd!23",
            TrustDirection="One-Way: Outgoing",
        )
    )
    assert code == "EntityAlreadyExistsException", f"unexpected code: {code}"
    assert message == (
        f"Trust already exists for directory: {directory_id} and remote domain: {remote_domain}. "
        f": RequestId: {request_id}"
    ), f"unexpected EntityAlreadyExistsException message: {message!r}"

    # Effect absent: still exactly one trust object for this remote domain.
    after = _trusts_for_domain(ds, directory_id, remote_domain)
    assert len(after) == 1 and after[0]["TrustId"] == trust_id, (
        f"expected exactly 1 trust ({trust_id}) for {remote_domain} after the rejected "
        f"duplicate, found {after!r}"
    )

    # Positive control: a trust to a genuinely different remote domain on the same
    # directory still succeeds, proving CreateTrust itself is not globally broken.
    other_domain = f"{ctx.unique_name('sim2real-trust-other-')}.test"
    other_trust_id = ds.create_trust(
        DirectoryId=directory_id,
        RemoteDomainName=other_domain,
        TrustPassword="YetAnotherPassw0rd!23",
        TrustDirection="One-Way: Outgoing",
    )["TrustId"]
    ctx.on_cleanup(lambda: _best_effort_delete_trust(ds, other_trust_id))
    assert other_trust_id != trust_id, (
        f"expected a distinct TrustId for {other_domain}, got the same id {trust_id} as "
        f"{remote_domain}"
    )

    other_after = _trusts_for_domain(ds, directory_id, other_domain)
    assert len(other_after) == 1 and other_after[0]["TrustId"] == other_trust_id, (
        f"expected exactly 1 trust ({other_trust_id}) for {other_domain}, found {other_after!r}"
    )


# ===== helpers =====


def _error(fn):
    """(Error.Code, Error.Message, RequestId) of the refusal fn() must raise; a success raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message", ""), e.response["ResponseMetadata"]["RequestId"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last state={last!r}")


def _wait_for_directory_stage(ctx, directory_id, target_stages, timeout_s=3600.0, interval_s=20.0):
    ds = ctx.client("ds")

    def probe():
        descs = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        stage = descs[0]["Stage"] if descs else None
        # Failed is terminal: a directory there never becomes Active.
        if stage == "Failed" and stage not in target_stages:
            raise AssertionError(f"directory {directory_id} reached Failed: {descs[0].get('StageReason')}")
        return stage

    return _poll_until(probe, lambda s: s in target_stages, timeout_s=timeout_s, interval_s=interval_s)


def _trusts_for_domain(ds, directory_id, remote_domain):
    trusts = ds.describe_trusts(DirectoryId=directory_id)["Trusts"]
    return [t for t in trusts if t.get("RemoteDomainName") == remote_domain]


def _best_effort_delete_trust(ds, trust_id):
    try:
        ds.delete_trust(TrustId=trust_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityDoesNotExistException":
            raise


def _create_vpc_with_subnets(ctx):
    ec2 = ctx.client("ec2")
    name_tag = ctx.unique_name("sim2real-ds-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.66.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name_tag}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
            "AvailabilityZones"
        ]
        if z.get("ZoneId") not in _DS_UNSUPPORTED_ZONE_IDS
    ][:2]
    if len(azs) < 2:
        raise AssertionError("region has fewer than 2 availability zones; cannot satisfy the "
                            "AWS Managed Microsoft AD 2-subnet requirement")
    subnet_ids = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.66.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": f"{name_tag}-{i}"}]}],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda s=sid: _delete_net(ec2, "delete_subnet", SubnetId=s))
    return vpc_id, subnet_ids


def _create_active_microsoft_ad(ctx, edition="Standard"):
    ds = ctx.client("ds")
    vpc_id, subnet_ids = _create_vpc_with_subnets(ctx)
    name = f"{ctx.unique_name('sim2real-ds-')}.test"
    resp = ds.create_microsoft_ad(
        Name=name,
        Password="Sim2Real-Passw0rd!23",
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Edition=edition,
        Description="sim2real behavioral check",
        Tags=[{"Key": "Name", "Value": name}],
    )
    directory_id = resp["DirectoryId"]

    def _cleanup():
        try:
            # Bounded so this wait and the 630 s network teardown fit the 1800 s cleanup budget.
            _wait_for_directory_stage(ctx, directory_id, {"Active", "Failed", "Impaired"}, timeout_s=1140, interval_s=20)
        except AssertionError:
            pass
        try:
            ds.delete_directory(DirectoryId=directory_id)
        except ClientError as e:
            if e.response["Error"]["Code"] != "EntityDoesNotExistException":
                raise

    ctx.on_cleanup(_cleanup)
    _wait_for_directory_stage(ctx, directory_id, {"Active"}, timeout_s=3600, interval_s=20)
    return directory_id, vpc_id, subnet_ids


# Subnet / VPC deletes fail with DependencyViolation while a deleted directory's ENIs linger: wait
# (bounded) for the ENIs to go, retry DependencyViolation in one window shared by all of a check's
# network deletes, then raise naming the ENIs still attached.
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
