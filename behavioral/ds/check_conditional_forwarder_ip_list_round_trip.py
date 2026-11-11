"""conditional-forwarder-ip-list-round-trip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "conditional-forwarder-ip-list-round-trip"
GROUP = "representation"
SERVICES = ["ds"]

_STRONG_PASSWORD = "Sim2Real-Test-Passw0rd1!"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeConditionalForwarders returns the DnsIpAddrs list unchanged and in order; after
    DeleteConditionalForwarder the filtered describe is empty (no error) and an update of the same
    forwarder fails EntityDoesNotExistException."""
    vpc_id, subnet_ids = _create_vpc_with_subnets(ctx)
    directory_id, _domain = _create_microsoft_ad(ctx, vpc_id, subnet_ids)
    _wait_for_directory_stage(ctx, directory_id, {"Active"})

    ds = ctx.client("ds")
    remote_domain = "sim2real-forwarder.example.org"
    ordered_ips = ["10.30.40.11", "10.30.40.222", "10.30.40.3"]

    ds.create_conditional_forwarder(
        DirectoryId=directory_id, RemoteDomainName=remote_domain, DnsIpAddrs=ordered_ips
    )
    ctx.on_cleanup(lambda: _cleanup_forwarder(ds, directory_id, remote_domain))

    result = ds.describe_conditional_forwarders(
        DirectoryId=directory_id, RemoteDomainNames=[remote_domain]
    )["ConditionalForwarders"]
    assert len(result) == 1, f"expected exactly one conditional forwarder, got {result!r}"
    assert result[0]["RemoteDomainName"] == remote_domain, (
        f"RemoteDomainName mismatch: expected {remote_domain!r}, got {result[0]['RemoteDomainName']!r}"
    )
    assert result[0]["DnsIpAddrs"] == ordered_ips, (
        f"DnsIpAddrs order/values not preserved: expected {ordered_ips!r}, got {result[0]['DnsIpAddrs']!r}"
    )

    ds.delete_conditional_forwarder(DirectoryId=directory_id, RemoteDomainName=remote_domain)
    gone = ds.describe_conditional_forwarders(
        DirectoryId=directory_id, RemoteDomainNames=[remote_domain]
    )["ConditionalForwarders"]
    assert gone == [], (
        f"expected no conditional forwarders for {remote_domain!r} after delete, got {gone!r}"
    )
    mutation_err = _client_error(
        lambda: ds.update_conditional_forwarder(
            DirectoryId=directory_id, RemoteDomainName=remote_domain, DnsIpAddrs=["10.30.40.99"]
        )
    )
    mutation_code = mutation_err.response["Error"]["Code"]
    assert mutation_code == "EntityDoesNotExistException", (
        f"expected EntityDoesNotExistException mutating a deleted forwarder, got code={mutation_code!r}"
    )
    expected_message = (
        f"The zone {remote_domain} was not found on the server. "
        f": RequestId: {mutation_err.response['ResponseMetadata']['RequestId']}"
    )
    message = mutation_err.response["Error"].get("Message")
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"


def _client_error(fn):
    """Call fn(); return the ClientError it raises. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _cleanup_forwarder(ds, directory_id: str, remote_domain: str) -> None:
    try:
        ds.delete_conditional_forwarder(DirectoryId=directory_id, RemoteDomainName=remote_domain)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityDoesNotExistException":
            raise


def _tag_spec(resource_type: str, name: str):
    return [
        {
            "ResourceType": resource_type,
            "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
        }
    ]


def _create_vpc_with_subnets(ctx):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-ds-net-")
    vpc_id = ec2.create_vpc(CidrBlock="10.67.0.0/16", TagSpecifications=_tag_spec("vpc", name))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"]][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.67.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=_tag_spec("subnet", f"{name}-{i}"),
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))
    return vpc_id, subnet_ids


def _create_microsoft_ad(ctx, vpc_id, subnet_ids):
    ds = ctx.client("ds")
    base = ctx.unique_name("sim2realds")
    domain_name = f"{base}.example.com"
    directory_id = ds.create_microsoft_ad(
        Name=domain_name,
        Password=_STRONG_PASSWORD,
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Edition="Standard",
        Tags=[{"Key": "Name", "Value": base}, {"Key": "sim2real", "Value": "true"}],
    )["DirectoryId"]
    ctx.on_cleanup(lambda: ds.delete_directory(DirectoryId=directory_id))
    return directory_id, domain_name


def _wait_for_directory_stage(ctx, directory_id, target_stages, timeout_s=3600.0, interval_s=30.0):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        last = desc["Stage"]
        if last in target_stages:
            return desc
        if last in ("Failed", "Inoperable"):
            raise AssertionError(f"directory {directory_id} entered terminal failure stage {last}")
        time.sleep(interval_s)
    raise AssertionError(f"directory {directory_id} stuck at {last}, expected one of {target_stages}")


# Network teardown waits (bounded) for AWS-managed ENIs to leave: directories and similar
# resources delete asynchronously, so an immediate DeleteSubnet/DeleteSecurityGroup/DeleteVpc
# fails DependencyViolation. Retry within one shared window, then raise naming the ENIs left.
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
