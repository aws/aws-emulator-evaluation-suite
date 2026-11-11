"""enable-radius-duplicate-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "enable-radius-duplicate-rejected"
GROUP = "error-semantics"
SERVICES = ["ds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """EnableRadius on a Microsoft AD directory that already has RADIUS enabled fails with ClientException
    and AWS's exact already-enabled message and keeps the original RadiusServers; after DisableRadius the
    same second EnableRadius succeeds."""
    directory_id = _create_microsoft_ad(ctx)
    _wait_for_directory_stage(ctx, directory_id, {"Active"})

    ds = ctx.client("ds")
    first_settings = {
        "RadiusServers": ["203.0.113.10"],
        "RadiusPort": 1812,
        "RadiusTimeout": 5,
        "RadiusRetries": 1,
        "SharedSecret": "Sim2Real-RadiusSecret-1",
        "AuthenticationProtocol": "PAP",
        "DisplayLabel": "sim2real-radius",
    }
    ds.enable_radius(DirectoryId=directory_id, RadiusSettings=first_settings)
    ctx.on_cleanup(lambda: _safe_disable_radius(ctx, directory_id))

    # Break exactly one thing: enable RADIUS again with different settings on the same
    # directory. Real AWS rejects the duplicate immediately, even while the first
    # EnableRadius is still asynchronously validating (RadiusStatus "Creating").
    second_settings = dict(first_settings, RadiusServers=["203.0.113.20"], SharedSecret="Sim2Real-RadiusSecret-2")
    code, message, request_id = _error(
        lambda: ds.enable_radius(DirectoryId=directory_id, RadiusSettings=second_settings)
    )
    assert code == "ClientException", f"expected ClientException, got {code!r} (message={message!r})"
    assert message == (
        "Could not enable radius as it is already enabled or currently being configured for "
        f"directory: {directory_id} : RequestId: {request_id}"
    ), f"unexpected ClientException message: {message!r}"

    # Effect absent: the original RADIUS server configuration must be unchanged.
    desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
    assert desc["RadiusSettings"]["RadiusServers"] == ["203.0.113.10"], (
        f"rejected EnableRadius must not change RadiusServers, got {desc['RadiusSettings']['RadiusServers']!r}"
    )

    # DisableRadius rejects a directory still in RadiusStatus "Creating" ("radius is not
    # enabled"); the RadiusServers above are unroutable TEST-NET-3 addresses, so real AWS's
    # own connectivity check for the RADIUS server will end in "Failed" rather than
    # "Completed" — either is a terminal state DisableRadius accepts, so wait for either.
    _wait_for_radius_terminal(ctx, directory_id)

    # Positive control: disabling and re-enabling RADIUS on the same directory succeeds.
    ds.disable_radius(DirectoryId=directory_id)
    _wait_for_radius_absent(ctx, directory_id)
    ds.enable_radius(DirectoryId=directory_id, RadiusSettings=second_settings)
    desc_after = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
    assert desc_after["RadiusSettings"]["RadiusServers"] == ["203.0.113.20"], (
        "the identical EnableRadius call must succeed once the directory has no RADIUS "
        f"configuration, got {desc_after['RadiusSettings']['RadiusServers']!r}"
    )


# ===== helpers =====


def _error(fn):
    """(Error.Code, Error.Message, RequestId) of the refusal fn() must raise; a success raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message", ""), e.response["ResponseMetadata"]["RequestId"]
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


def _default_vpc_two_azs(ctx):
    ec2 = ctx.client("ec2")
    for vpc in ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", []):
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
        subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
        by_az: dict[str, str] = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            azs = sorted(by_az)
            return vpc["VpcId"], [by_az[azs[0]], by_az[azs[1]]]
    # No existing VPC has subnets in 2 distinct AZs (a freshly provisioned account may have
    # no shared network at all): provision our own rather than depending on ambient state.
    return _create_two_az_vpc(ctx)


def _create_two_az_vpc(ctx):
    ec2 = ctx.client("ec2")
    azs = [
        a["ZoneName"]
        for a in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
            "AvailabilityZones"
        ][:2]
    ]
    if len(azs) < 2:
        raise AssertionError("region does not expose two available AZs to place directory subnets")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.91.0.0/16",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ds-vpc-")}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.91.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ds-subnet-")}]}
            ],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
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
    )["DirectoryId"]
    ctx.on_cleanup(lambda: _safe_delete_directory(ctx, directory_id))
    return directory_id


def _safe_delete_directory(ctx, directory_id):
    """Delete the directory and wait until it is gone. A refused DeleteDirectory is ignored; a
    directory still present after the wait raises, since its ENIs would keep the shared network
    from being deleted."""
    ds = ctx.client("ds")
    try:
        _delete_directory_and_wait(ds, directory_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DirectoryDoesNotExistException",
            "EntityDoesNotExistException",
        ):
            raise


def _safe_disable_radius(ctx, directory_id):
    """Teardown: DisableRadius answers ClientException "... radius is not enabled ..." while
    RadiusStatus is still Creating or once RADIUS is already off. Either is left to the directory
    teardown, because DeleteDirectory removes the RADIUS configuration with the directory."""
    ds = ctx.client("ds")
    try:
        ds.disable_radius(DirectoryId=directory_id)
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] == "ClientException" and "radius is not enabled" in err.get("Message", ""):
            return
        if err["Code"] not in (
            "DirectoryDoesNotExistException",
            "EntityDoesNotExistException",
        ):
            raise


def _directory_stage(ctx, directory_id):
    ds = ctx.client("ds")
    resp = ds.describe_directories(DirectoryIds=[directory_id])
    descs = resp["DirectoryDescriptions"]
    return descs[0]["Stage"] if descs else None


def _wait_for_directory_stage(ctx, directory_id, target_stages, timeout_s=2700, interval_s=20):
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


def _wait_for_radius_absent(ctx, directory_id, timeout_s=180, interval_s=10):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        if not desc.get("RadiusSettings") or not desc["RadiusSettings"].get("RadiusServers"):
            return
        time.sleep(interval_s)
    raise AssertionError(f"RADIUS settings for {directory_id} were never cleared after DisableRadius")


def _wait_for_radius_terminal(ctx, directory_id, timeout_s=600, interval_s=15):
    """Wait for RadiusStatus to leave "Creating". "Completed" and "Failed" are both
    terminal states DisableRadius will accept; which one is reached depends on whether
    the configured RadiusServers are actually reachable, which this check does not need."""
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        last = desc.get("RadiusStatus")
        if last in ("Completed", "Failed"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"RadiusStatus for {directory_id} was still {last!r} after {timeout_s}s")


# AWS-managed ENIs leave a VPC asynchronously after their owner's delete returns, so a network
# delete waits (bounded, within the cleanup budget) for them and retries DependencyViolation, then
# raises naming the ENIs still attached. Teardown-only: run() never calls this.
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
