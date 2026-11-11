"""create-conditional-forwarder-duplicate-name-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-conditional-forwarder-duplicate-name-rejected"
GROUP = "error-semantics"
SERVICES = ["ds"]

_DS_PASSWORD = "Sim2Real-Test-P@ssw0rd1"

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateConditionalForwarder for a remote domain that already has a forwarder fails
    EntityAlreadyExistsException and leaves the original DNS IPs untouched, while a forwarder
    for a different domain still succeeds."""
    ds = ctx.client("ds")
    directory_id, _vpc_id, _subnet_ids = _create_microsoft_ad(ctx)
    _wait_for_stage(ctx, directory_id, "Active")

    label = "".join(c for c in ctx.unique_name("sim2realfwd").lower() if c.isalnum() or c == "-")
    remote_domain = f"{label.strip('-') or 'sim2realfwd'}.example.org"

    ds.create_conditional_forwarder(
        DirectoryId=directory_id, RemoteDomainName=remote_domain, DnsIpAddrs=["203.0.113.10"]
    )
    ctx.on_cleanup(
        lambda: ds.delete_conditional_forwarder(
            DirectoryId=directory_id, RemoteDomainName=remote_domain
        )
    )

    code, message, request_id = _error(
        lambda: ds.create_conditional_forwarder(
            DirectoryId=directory_id, RemoteDomainName=remote_domain, DnsIpAddrs=["203.0.113.11"]
        )
    )
    assert code == "EntityAlreadyExistsException", f"expected EntityAlreadyExistsException, got {code!r}"
    # The message names the directory's DNS server, which the check cannot know, so the parts
    # around it are exact.
    assert message.startswith(f"Failed to create zone {remote_domain} on server ") and message.endswith(
        f". A conditional forwarding zone already exists for that name.  : RequestId: {request_id}"
    ), f"unexpected EntityAlreadyExistsException message: {message!r}"

    forwarders = ds.describe_conditional_forwarders(
        DirectoryId=directory_id, RemoteDomainNames=[remote_domain]
    )["ConditionalForwarders"]
    assert len(forwarders) == 1, forwarders
    assert forwarders[0]["DnsIpAddrs"] == ["203.0.113.10"], forwarders  # unchanged by the duplicate

    # Positive control: a forwarder for a genuinely different remote domain still succeeds.
    other_domain = f"other-{label.strip('-') or 'sim2realfwd'}.example.org"
    ds.create_conditional_forwarder(
        DirectoryId=directory_id, RemoteDomainName=other_domain, DnsIpAddrs=["203.0.113.12"]
    )
    ctx.on_cleanup(
        lambda: ds.delete_conditional_forwarder(
            DirectoryId=directory_id, RemoteDomainName=other_domain
        )
    )

    # Independent read at the destination: the positive control actually landed, with
    # its own DnsIpAddrs, and did not merge into or alias the rejected duplicate's entry.
    other_forwarders = ds.describe_conditional_forwarders(
        DirectoryId=directory_id, RemoteDomainNames=[other_domain]
    )["ConditionalForwarders"]
    assert len(other_forwarders) == 1, other_forwarders
    assert other_forwarders[0]["DnsIpAddrs"] == ["203.0.113.12"], other_forwarders


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message, RequestId). Raises if the call succeeded."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        request_id = (exc.response.get("ResponseMetadata") or {}).get("RequestId")
        return err.get("Code"), err.get("Message"), request_id
    raise AssertionError(f"expected a ClientError, call succeeded with {resp!r}")


def _two_az_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
            ]
        )["Subnets"]
        by_az = {}
        for s in subnets:
            if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS:
                by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            return vpc_id, list(by_az.values())[:2]

    azs = [
        a["ZoneName"]
        for a in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
        if a.get("ZoneId") not in _DS_UNSUPPORTED_ZONE_IDS
    ][:2]
    if len(azs) < 2:
        raise AssertionError("region does not expose two available AZs to place directory subnets")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.90.0.0/16",
        TagSpecifications=[
            {
                "ResourceType": "vpc",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ds-vpc-")}],
            }
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.90.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {
                    "ResourceType": "subnet",
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ds-subnet-")}],
                }
            ],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _create_microsoft_ad(ctx, edition="Standard"):
    ds = ctx.client("ds")
    vpc_id, subnet_ids = _two_az_subnets(ctx)
    label = "".join(c for c in ctx.unique_name("sim2realds").lower() if c.isalnum() or c == "-")
    label = label.strip("-") or "sim2realds"
    name = f"{label}.example.com"
    directory_id = ds.create_microsoft_ad(
        Name=name,
        Password=_DS_PASSWORD,
        Edition=edition,
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
    )["DirectoryId"]
    ctx.on_cleanup(lambda: _delete_directory_and_wait(ds, directory_id))
    return directory_id, vpc_id, subnet_ids


def _wait_for_stage(ctx, directory_id, target_stage="Active", timeout_s=3600.0, interval_s=30.0):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    last_stage = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        last_stage = desc["Stage"]
        if last_stage == target_stage:
            return desc
        if last_stage in ("Failed", "Inoperable"):
            raise AssertionError(f"directory {directory_id} reached terminal stage {last_stage}")
        time.sleep(interval_s)
    raise AssertionError(
        f"directory {directory_id} did not reach {target_stage} within {timeout_s}s "
        f"(last stage {last_stage})"
    )


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



def _delete_directory_and_wait(ds, directory_id, timeout_s=1140.0, interval_s=30.0):
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
                except ClientError as exc:
                    if exc.response["Error"]["Code"] not in (
                        "DirectoryDoesNotExistException",
                        "EntityDoesNotExistException",
                    ):
                        raise
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
