"""create-conditional-forwarder-duplicate-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-conditional-forwarder-duplicate-rejected"
GROUP = "error-semantics"
SERVICES = ["ds"]

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

_PASSWORD = "Sim2Real-Passw0rd!23"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second conditional forwarder for an already-forwarded remote domain is rejected with
    EntityAlreadyExistsException and AWS's zone-exists message and leaves the original DnsIpAddrs
    unmodified, while a forwarder for a different domain on the same directory still succeeds."""
    ds = ctx.client("ds")
    directory_id = _create_active_microsoft_ad(ctx)
    remote_domain = "sim2real-forwarder.example.test"
    original_ips = ["198.51.100.11"]

    # Positive control: creating the first conditional forwarder succeeds.
    ds.create_conditional_forwarder(
        DirectoryId=directory_id, RemoteDomainName=remote_domain, DnsIpAddrs=original_ips
    )
    ctx.on_cleanup(lambda: _best_effort_delete_forwarder(ds, directory_id, remote_domain))

    # Negative: a second create for the same remote domain is rejected.
    code, message, request_id = _error(
        lambda: ds.create_conditional_forwarder(
            DirectoryId=directory_id, RemoteDomainName=remote_domain, DnsIpAddrs=["198.51.100.99"]
        )
    )
    assert code == "EntityAlreadyExistsException", f"unexpected code: {code}"
    # The message names the directory's DNS server, which the check cannot know, so the parts
    # around it are exact.
    assert message.startswith(f"Failed to create zone {remote_domain} on server ") and message.endswith(
        f". A conditional forwarding zone already exists for that name.  : RequestId: {request_id}"
    ), f"unexpected EntityAlreadyExistsException message: {message!r}"

    # Effect absent: the forwarder still has its original DnsIpAddrs, not the duplicate's.
    forwarders = ds.describe_conditional_forwarders(
        DirectoryId=directory_id, RemoteDomainNames=[remote_domain]
    )["ConditionalForwarders"]
    assert len(forwarders) == 1
    assert forwarders[0]["DnsIpAddrs"] == original_ips, forwarders[0]["DnsIpAddrs"]

    # Positive control: a forwarder for a genuinely different domain on the same
    # directory still creates fine.
    other_domain = "sim2real-other-forwarder.example.test"
    other_ips = ["198.51.100.22"]
    ds.create_conditional_forwarder(
        DirectoryId=directory_id, RemoteDomainName=other_domain, DnsIpAddrs=other_ips
    )
    ctx.on_cleanup(lambda: _best_effort_delete_forwarder(ds, directory_id, other_domain))
    other = ds.describe_conditional_forwarders(
        DirectoryId=directory_id, RemoteDomainNames=[other_domain]
    )["ConditionalForwarders"]
    assert len(other) == 1 and other[0]["DnsIpAddrs"] == other_ips, other


# ===== helpers =====


def _error(fn):
    """(Error.Code, Error.Message, RequestId) of the refusal fn() must raise; a success raises."""
    try:
        resp = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message", ""), e.response["ResponseMetadata"]["RequestId"]
    raise AssertionError(f"expected a ClientError, call succeeded with {resp!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last state={last!r}")


def _wait_for_directory_stage(ctx, directory_id, target_stages, timeout_s=2700.0, interval_s=20.0):
    ds = ctx.client("ds")

    def probe():
        descs = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        return descs[0]["Stage"] if descs else None

    return _poll_until(probe, lambda s: s in target_stages, timeout_s=timeout_s, interval_s=interval_s)


def _best_effort_delete_forwarder(ds, directory_id, remote_domain):
    try:
        ds.delete_conditional_forwarder(DirectoryId=directory_id, RemoteDomainName=remote_domain)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DirectoryDoesNotExistException",
            "EntityDoesNotExistException",
        ):
            raise


def _tag_spec(resource_type, name):
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "ds-behavioral"}],
    }


def _create_vpc_with_subnets(ctx):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-ds-vpc-")
    vpc_id = ec2.create_vpc(CidrBlock="10.95.0.0/16", TagSpecifications=[_tag_spec("vpc", name)])[
        "Vpc"
    ]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    azs = [
        az["ZoneName"]
        for az in ec2.describe_availability_zones()["AvailabilityZones"]
        if az["State"] == "available" and az.get("ZoneId") not in _DS_UNSUPPORTED_ZONE_IDS
    ][:2]
    if len(azs) < 2:
        raise AssertionError("region does not expose at least 2 available AZs for directory subnets")

    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.95.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec("subnet", f"{name}-{i}")],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _create_active_microsoft_ad(ctx):
    ds = ctx.client("ds")
    vpc_id, subnet_ids = _create_vpc_with_subnets(ctx)
    name = f"{ctx.unique_name('sim2real-ds-')}.test"
    resp = ds.create_microsoft_ad(
        Name=name,
        Password=_PASSWORD,
        Edition="Standard",
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Description="sim2real behavioral check",
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
    _wait_for_directory_stage(ctx, directory_id, {"Active"}, timeout_s=2700, interval_s=20)
    return directory_id


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
