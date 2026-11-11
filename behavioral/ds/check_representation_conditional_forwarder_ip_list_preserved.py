"""representation-conditional-forwarder-ip-list-preserved."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "representation-conditional-forwarder-ip-list-preserved"
GROUP = "representation"
SERVICES = ["ds"]

_PASSWORD = "Sim2Real-Ds-Pw9!"
_DIR_ACTIVE_TIMEOUT_S = 3600.0
# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The exact ordered list of DNS IP addresses supplied to CreateConditionalForwarder
    is returned unchanged and in the same order by DescribeConditionalForwarders."""
    ds = ctx.client("ds")
    vpc = _create_vpc_with_subnets(ctx)
    domain = ctx.unique_name("sim2real-ds-cf-").lower() + ".test"

    directory_id = ds.create_microsoft_ad(
        Name=domain,
        Password=_PASSWORD,
        Edition="Standard",
        VpcSettings={"VpcId": vpc["vpc_id"], "SubnetIds": vpc["subnet_ids"]},
    )["DirectoryId"]
    ctx.on_cleanup(lambda: ds.delete_directory(DirectoryId=directory_id))
    _wait_for_directory_stage(ctx, ds, directory_id, {"Active"}, _DIR_ACTIVE_TIMEOUT_S)

    remote_domain = "corp." + ctx.unique_name("sim2real-cf-order-").lower().replace("_", "-") + ".test"
    ip_list = ["198.51.100.4", "198.51.100.1", "198.51.100.9", "198.51.100.2"]
    _retry_directory_settling(
        lambda: ds.create_conditional_forwarder(
            DirectoryId=directory_id, RemoteDomainName=remote_domain, DnsIpAddrs=ip_list
        )
    )

    forwarders = ds.describe_conditional_forwarders(
        DirectoryId=directory_id, RemoteDomainNames=[remote_domain]
    )["ConditionalForwarders"]
    assert len(forwarders) == 1, f"expected exactly one conditional forwarder, got {forwarders!r}"
    assert forwarders[0]["RemoteDomainName"] == remote_domain, (
        f"expected RemoteDomainName {remote_domain!r}, got {forwarders[0]['RemoteDomainName']!r}"
    )
    assert forwarders[0]["DnsIpAddrs"] == ip_list, (
        f"DNS IP order/values not preserved: wrote {ip_list!r}, read back {forwarders[0]['DnsIpAddrs']!r}"
    )


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _create_vpc_with_subnets(ctx) -> dict:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-ds-vpc-")
    vpc_id = ec2.create_vpc(CidrBlock="10.93.0.0/16", TagSpecifications=[_tag_spec("vpc", name)])[
        "Vpc"
    ]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    azs = [
        az["ZoneName"]
        for az in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
        if az.get("ZoneId") not in _DS_UNSUPPORTED_ZONE_IDS
    ][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.93.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec("subnet", f"{name}-{i}")],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids}


def _retry_directory_settling(fn, attempts: int = 10, delay_s: float = 12.0):
    """A directory that just reached Active can still answer a mutating call with
    DirectoryUnavailableException or ServiceException for a few more minutes while its
    domain controllers finish settling; retry with backoff rather than treat that
    transient window as a fidelity finding."""
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("DirectoryUnavailableException", "ServiceException"):
                last_exc = exc
                time.sleep(delay_s)
                continue
            raise
    raise last_exc


def _wait_for_directory_stage(ctx, ds, directory_id, target_stages, timeout_s, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    stage = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        stage = desc["Stage"]
        if stage in target_stages:
            return desc
        if stage in ("Failed", "Inoperable"):
            raise AssertionError(f"directory {directory_id} entered terminal stage {stage}")
        time.sleep(interval_s)
    raise AssertionError(
        f"directory {directory_id} did not reach {target_stages} within {timeout_s}s "
        f"(last stage={stage})"
    )


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
        _time.sleep(10)
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
        _time.sleep(10)


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
