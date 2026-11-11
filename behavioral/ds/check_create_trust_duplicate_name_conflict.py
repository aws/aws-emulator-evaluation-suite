"""create-trust-duplicate-name-conflict."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "create-trust-duplicate-name-conflict"
GROUP = "error-semantics"
SERVICES = ["ds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a second trust with a RemoteDomainName that already has a trust on the
    directory raises EntityAlreadyExistsException, and only the original trust exists.
    """
    directory_id = _create_microsoft_ad(ctx)
    _wait_for_directory_stage(ctx, directory_id, {"Active"})

    ds = ctx.client("ds")
    remote_domain = (ctx.unique_name("sim2real-trust-").replace("_", "-") + ".test").lower()
    first_trust_id = ds.create_trust(
        DirectoryId=directory_id,
        RemoteDomainName=remote_domain,
        TrustPassword="Sim2Real-TestPW1",
        TrustDirection="One-Way: Outgoing",
    )["TrustId"]
    ctx.on_cleanup(lambda: _safe_delete_trust(ctx, first_trust_id))

    # Break exactly one thing: request a second trust for the identical remote domain. No
    # wait on the first trust's TrustState: CreateTrust's uniqueness check on RemoteDomainName
    # is enforced against the trust record itself, not its (async, and for an unresolvable
    # .test domain, eventually Failed) verification outcome.

    code, message, request_id = _error(
        lambda: ds.create_trust(
            DirectoryId=directory_id,
            RemoteDomainName=remote_domain,
            TrustPassword="Sim2Real-TestPW1-Other",
            TrustDirection="One-Way: Outgoing",
        )
    )
    assert code == "EntityAlreadyExistsException", f"unexpected error code for duplicate trust: {code!r}"
    expected_message = (
        f"Trust already exists for directory: {directory_id} and remote domain: "
        f"{remote_domain}. : RequestId: {request_id}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: exactly one trust for that remote domain, not two.
    trusts = ds.describe_trusts(DirectoryId=directory_id)["Trusts"]
    matching = [t for t in trusts if t["RemoteDomainName"] == remote_domain]
    assert len(matching) == 1, f"expected exactly 1 trust for {remote_domain}, found {len(matching)}"
    assert matching[0]["TrustId"] == first_trust_id, (
        f"expected the surviving trust to be the original {first_trust_id}, found {matching[0]['TrustId']}"
    )

    # Positive control: a trust to a genuinely different remote domain succeeds, proving
    # CreateTrust is not globally broken -- and the terminal read is independent of the
    # mutating call, at the destination (describe_trusts), not the create response.
    other_domain = ctx.unique_name("sim2real-trust-other-").replace("_", "-") + ".test"
    other_trust_id = ds.create_trust(
        DirectoryId=directory_id,
        RemoteDomainName=other_domain,
        TrustPassword="Sim2Real-TestPW1",
        TrustDirection="One-Way: Outgoing",
    )["TrustId"]
    ctx.on_cleanup(lambda: _safe_delete_trust(ctx, other_trust_id))
    assert other_trust_id != first_trust_id, "second create_trust reused the first trust's id"

    all_trusts = ds.describe_trusts(DirectoryId=directory_id)["Trusts"]
    domains = {t["RemoteDomainName"] for t in all_trusts}
    assert remote_domain in domains and other_domain in domains, (
        f"expected both {remote_domain!r} and {other_domain!r} visible via describe_trusts, "
        f"found {domains!r}"
    )


# ===== helpers =====


def _error(fn):
    """Call fn(); return the (Code, Message, RequestId) of the ClientError it raises. An
    unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return (
            e.response["Error"]["Code"],
            e.response["Error"].get("Message"),
            e.response.get("ResponseMetadata", {}).get("RequestId"),
        )
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _default_vpc_two_azs(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
        subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
        by_az: dict[str, str] = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            azs = sorted(by_az)
            return vpc_id, [by_az[azs[0]], by_az[azs[1]]]
    # No usable shared network (a freshly provisioned account may not have one) -- create our
    # own rather than fail outright.
    return _own_vpc_two_azs(ctx)


def _own_vpc_two_azs(ctx):
    ec2 = ctx.client("ec2")
    tag = ctx.unique_name("sim2real-ds-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.77.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": tag}]}],
    )["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ctx.on_cleanup(lambda: _safe_delete_vpc(ctx, vpc_id))

    azs = [z["ZoneName"] for z in ec2.describe_availability_zones()["AvailabilityZones"]][:2]
    if len(azs) < 2:
        raise AssertionError(f"region has fewer than 2 availability zones (found {len(azs)})")
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.77.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": f"{tag}{i}"}]}
            ],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)
        ctx.on_cleanup(lambda sid=subnet_id: _safe_delete_subnet(ctx, sid))
    return vpc_id, subnet_ids


def _create_microsoft_ad(ctx, password="Sim2Real-TestPW1"):
    ds = ctx.client("ds")
    vpc_id, subnet_ids = _default_vpc_two_azs(ctx)
    name = ctx.unique_name("sim2real-msad-") + ".test"
    directory_id = ds.create_microsoft_ad(
        Name=name,
        Password=password,
        Edition="Standard",
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Tags=[{"Key": "sim2real", "Value": "behavioral"}, {"Key": "sim2real-check", "Value": CHECK}],
    )["DirectoryId"]
    ctx.on_cleanup(lambda: _safe_delete_directory(ctx, directory_id))
    return directory_id


def _safe_delete_directory(ctx, directory_id):
    """Delete the directory and wait until it is gone; an already-gone directory is fine, and a
    refused delete or a directory still present after the wait raises."""
    ds = ctx.client("ds")
    try:
        _delete_directory_and_wait(ds, directory_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DirectoryDoesNotExistException",
            "EntityDoesNotExistException",
        ):
            raise


def _safe_delete_trust(ctx, trust_id):
    ds = ctx.client("ds")
    try:
        ds.delete_trust(TrustId=trust_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityDoesNotExistException":
            raise


def _safe_delete_subnet(ctx, subnet_id):
    ec2 = ctx.client("ec2")
    try:
        _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidSubnetID.NotFound":
            raise


def _safe_delete_vpc(ctx, vpc_id):
    ec2 = ctx.client("ec2")
    try:
        _delete_net(ec2, "delete_vpc", VpcId=vpc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVpcID.NotFound":
            raise


def _directory_stage(ctx, directory_id):
    ds = ctx.client("ds")
    resp = ds.describe_directories(DirectoryIds=[directory_id])
    descs = resp["DirectoryDescriptions"]
    return descs[0]["Stage"] if descs else None


def _wait_for_directory_stage(ctx, directory_id, target_stages, timeout_s=3600, interval_s=20):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _directory_stage(ctx, directory_id)
        if last in target_stages:
            return last
        if last in ("Failed", "Impaired", "Inoperable") and last not in target_stages:
            raise AssertionError(f"directory {directory_id} reached unexpected stage {last}")
        time.sleep(interval_s)
    raise AssertionError(
        f"directory {directory_id} did not reach {target_stages} within {timeout_s}s (last={last})"
    )


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
