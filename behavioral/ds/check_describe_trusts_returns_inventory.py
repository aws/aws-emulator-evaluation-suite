"""describe-trusts-returns-inventory."""

from __future__ import annotations

import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "describe-trusts-returns-inventory"
GROUP = 'lifecycle'
SERVICES = ['ds']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTrusts scoped by DirectoryId is empty before CreateTrust, returns the created trust's
    fields once it exists (also visible unscoped), and is empty again after DeleteTrust."""
    ds = ctx.client("ds")
    vpc_id, subnet_ids = _create_vpc_with_two_subnets(ctx)
    directory_id = _create_active_microsoft_ad(ctx, ds, vpc_id, subnet_ids)

    before = ds.describe_trusts(DirectoryId=directory_id)["Trusts"]
    assert before == [], f"expected no trusts before CreateTrust, got {before!r}"

    remote_domain = f"{ctx.unique_name('sim2real-remote-')}.example.com"
    trust_id = ds.create_trust(
        DirectoryId=directory_id,
        RemoteDomainName=remote_domain,
        TrustPassword=_ad_password(),
        TrustDirection="One-Way: Outgoing",
    )["TrustId"]

    def _cleanup_trust():
        try:
            ds.delete_trust(TrustId=trust_id)
        except ClientError as e:
            if e.response["Error"]["Code"] != "EntityDoesNotExistException":
                raise

    ctx.on_cleanup(_cleanup_trust)

    scoped = _poll_until(
        ctx,
        lambda: ds.describe_trusts(DirectoryId=directory_id)["Trusts"],
        lambda ts: len(ts) == 1,
        timeout_s=120.0,
    )
    trust = scoped[0]
    assert trust["TrustId"] == trust_id, trust
    assert trust["DirectoryId"] == directory_id, trust
    assert trust["RemoteDomainName"] == remote_domain, trust
    assert trust["TrustDirection"] == "One-Way: Outgoing", trust

    unscoped = ds.describe_trusts()["Trusts"]
    assert any(t["TrustId"] == trust_id for t in unscoped), (
        f"trust {trust_id} missing from the unscoped account-wide inventory: {unscoped!r}"
    )

    ds.delete_trust(TrustId=trust_id)

    after = _poll_until(
        ctx,
        lambda: ds.describe_trusts(DirectoryId=directory_id)["Trusts"],
        lambda ts: ts == [],
        timeout_s=900.0,
    )
    assert after == [], f"expected trust removed from inventory after delete, got {after!r}"


# ===== helpers =====

def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx) -> bool:
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, *, timeout_s):
    """Poll every 2 s until predicate holds, for timeout_s bounded by the runner's time left."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"waiting on {last!r}: the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s:.0f}s (last={last!r})")


def _ad_password() -> str:
    return "Sim2Real!" + secrets.token_hex(8) + "Aa1"


def _tag_spec(ctx, resource_type: str, kind: str):
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-ds-{kind}-")}],
    }


def _create_vpc_with_two_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.174.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc", "vpc")])["Vpc"]["VpcId"]

    def _cleanup_vpc():
        try:
            _delete_net(ec2, "delete_vpc", VpcId=vpc_id)
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidVpcID.NotFound":
                raise

    ctx.on_cleanup(_cleanup_vpc)
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
    az_names = [az["ZoneName"] for az in azs[:2]]
    if len(az_names) < 2:
        raise AssertionError("region does not have 2 available AZs")

    subnet_ids = []
    for i, az in enumerate(az_names):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.174.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec(ctx, "subnet", "subnet")],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)

        def _cleanup_subnet(sid=subnet_id):
            try:
                _delete_net(ec2, "delete_subnet", SubnetId=sid)
            except ClientError as e:
                if e.response["Error"]["Code"] != "InvalidSubnetID.NotFound":
                    raise

        ctx.on_cleanup(_cleanup_subnet)
    return vpc_id, subnet_ids


def _create_active_microsoft_ad(ctx, ds, vpc_id, subnet_ids) -> str:
    name = f"{ctx.unique_name('sim2real-msad-')}.example.com"
    directory_id = ds.create_microsoft_ad(
        Name=name,
        Password=_ad_password(),
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Edition="Standard",
        Tags=[{"Key": "Name", "Value": name}],
    )["DirectoryId"]
    ctx.on_cleanup(lambda: _delete_directory(ds, directory_id))

    stage = _poll_until(
        ctx,
        lambda: ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]["Stage"],
        lambda s: s in ("Active", "Failed"),
        timeout_s=5400.0,
    )
    if stage != "Active":
        raise AssertionError(f"directory reached terminal stage {stage!r} instead of Active")
    return directory_id


def _delete_directory(ds, directory_id: str) -> None:
    try:
        ds.delete_directory(DirectoryId=directory_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "EntityDoesNotExistException":
            raise


# Subnet / VPC deletes fail with DependencyViolation while a deleted directory's ENIs linger: wait
# (bounded) for the ENIs to go, retry DependencyViolation in one window shared by all of a check's
# network deletes, then raise naming the ENIs still attached.
_NET_TEARDOWN_S = 1500.0  # the directory delete does not wait, so the network window takes the budget
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
