"""simple-ad-small-lifecycle-to-active-then-deleted."""
from __future__ import annotations

import ipaddress
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "simple-ad-small-lifecycle-to-active-then-deleted"
GROUP = 'lifecycle'
SERVICES = ['ds']
# Also calls ec2 to build the VPC substrate and to verify the directory's ENIs; SERVICES lists
# only the service under test.

# Billable: an AWS Managed Microsoft AD Standard bills per hour from creation until deletion
# (~$0.12/hr) and takes about 24 minutes to reach Active. Simple AD is not open to new customers
# (CreateDirectory refuses it with ClientException), so the cheapest managed directory is used.
_VPC_CIDR = "10.241.0.0/16"
_SUBNET_CIDRS = ("10.241.1.0/24", "10.241.2.0/24")
# Stages a healthy create may pass through, per the DirectoryStage enum.
_CREATE_TRANSIENT = {"Requested", "Creating", "Created"}
_CREATE_TERMINAL = {"Active", "Inoperable", "Impaired", "Failed", "Deleted"}


# ===== helpers =====
def _error(fn):
    """Call fn(); return the botocore Error dict plus its RequestId if a ClientError was raised, else {}.

    The Message matters as much as the Code here: ds reports "does not exist" and "Invalid
    directory ID(s)" through the SAME EntityDoesNotExistException, and which one it chooses is how
    it distinguishes an id it once issued from one it never did.
    """
    try:
        fn()
    except ClientError as exc:
        return {**(exc.response.get("Error", {}) or {}), "RequestId": exc.response["ResponseMetadata"]["RequestId"]}
    return {}


def _absent_directory_id(ds) -> str:
    """A syntactically valid DirectoryId that this account has never been issued.

    Verified against the unfiltered inventory rather than assumed: the contrast assertion this
    feeds is only meaningful if the id really is unknown to the service.
    """
    owned = {
        d.get("DirectoryId")
        for d in ds.describe_directories().get("DirectoryDescriptions", [])
    }
    for candidate in (f"d-{n:010x}" for n in range(1, 32)):
        if candidate not in owned:
            return candidate
    raise AssertionError(f"could not find an unissued DirectoryId; owned={owned}")


def _poll(fn, pred, *, timeout_s: float, interval_s: float = 15.0):
    """Poll fn() until pred(result) is true or the deadline passes. Returns the last result."""
    deadline = time.monotonic() + timeout_s
    while True:
        result = fn()
        if pred(result):
            return result
        if time.monotonic() >= deadline:
            return result
        time.sleep(interval_s)


def _tag_spec(resource_type, name):
    """TagSpecifications so the EC2 resource is attributable the instant it exists."""
    return [{
        "ResourceType": resource_type,
        "Tags": [
            {"Key": "Name", "Value": name},
            {"Key": "sim2real", "Value": "behavioral"},
            {"Key": "sim2real-check", "Value": CHECK},
        ],
    }]


def _describe(ds, directory_id):
    """The DirectoryDescription for directory_id, or None once it is gone."""
    try:
        found = ds.describe_directories(DirectoryIds=[directory_id])
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in {
            "EntityDoesNotExistException",
            "DirectoryDoesNotExistException",
        }:
            return None
        raise
    descriptions = found.get("DirectoryDescriptions") or []
    return descriptions[0] if descriptions else None


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Managed Microsoft AD Standard reaches Active with a populated DirectoryDescription whose
    DnsIpAddrs are its own ENIs in the caller's subnets; once deleted, DescribeDirectories returns an
    empty collection while other operations refuse the id with a message distinct from a never-issued one."""

    ds = ctx.client("ds")
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-")
    fqdn = f"{name}.example.com"

    zones = sorted(
        z["ZoneName"]
        # Standard zones only: an opted-in Local Zone sorts first and ds cannot place a directory
        # controller in it.
        for z in ec2.describe_availability_zones(
            Filters=[
                {"Name": "state", "Values": ["available"]},
                {"Name": "zone-type", "Values": ["availability-zone"]},
                {"Name": "opt-in-status", "Values": ["opt-in-not-required"]},
            ]
        ).get("AvailabilityZones", [])
    )
    if len(zones) < 2:
        raise AssertionError(
            f"a ds directory is Multi-AZ by requirement and needs 2 availability zones, "
            f"this region reports {zones}"
        )

    vpc_id = ec2.create_vpc(
        CidrBlock=_VPC_CIDR, TagSpecifications=_tag_spec("vpc", name)
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    subnet_ids = []
    subnet_az = {}
    for index, (cidr, zone) in enumerate(zip(_SUBNET_CIDRS, zones[:2])):
        subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=cidr,
            AvailabilityZone=zone,
            TagSpecifications=_tag_spec("subnet", f"{name}-{index}"),
        )["Subnet"]
        subnet_ids.append(subnet["SubnetId"])
        subnet_az[subnet["SubnetId"]] = zone
        ctx.on_cleanup(lambda sid=subnet["SubnetId"]: ec2.delete_subnet(SubnetId=sid))

    created = ds.create_microsoft_ad(
        Name=fqdn,
        ShortName="SIM2REAL",
        Password="Sim2Real#Pass99",
        Edition="Standard",
        Description="sim2real behavioral lifecycle check",
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
    )
    directory_id = created.get("DirectoryId")
    assert directory_id and directory_id.startswith("d-"), (
        f"CreateMicrosoftAD must mint a d- DirectoryId, got {created}"
    )

    # Registered LAST, so LIFO cleanup reaps the directory FIRST — before the subnets and VPC it
    # holds ENIs in. Registered immediately after creation, before any assertion can fail.
    def _reap():
        try:
            ds.delete_directory(DirectoryId=directory_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "EntityDoesNotExistException":
                raise
        # Bounded so the subnet and VPC deletes after it still fit the suite's teardown budget.
        left = _poll(
            lambda: _describe(ds, directory_id),
            lambda desc: desc is None,
            timeout_s=1500.0,
            interval_s=30.0,
        )
        if left is not None:
            raise RuntimeError(
                f"directory {directory_id} is still {left.get('Stage')!r} after DeleteDirectory"
            )

    ctx.on_cleanup(_reap)

    # --- Drive to a terminal stage, recording every stage we observe.
    observed = []

    def _stage_probe():
        desc = _describe(ds, directory_id)
        stage = (desc or {}).get("Stage")
        if stage and (not observed or observed[-1] != stage):
            observed.append(stage)
        return desc

    desc = _poll(
        _stage_probe,
        lambda d: d is not None and d.get("Stage") in _CREATE_TERMINAL,
        timeout_s=3600.0,
        interval_s=30.0,
    )
    assert desc is not None, (
        f"directory {directory_id} vanished while being created; stages observed: {observed}"
    )
    assert desc.get("Stage") == "Active", (
        f"a Standard Managed Microsoft AD must reach Stage 'Active', got {desc.get('Stage')!r} "
        f"(StageReason={desc.get('StageReason')!r}); stages observed: {observed}"
    )
    assert set(observed) <= _CREATE_TRANSIENT | {"Active"}, (
        f"the create path passed through an illegal stage: {observed} — only "
        f"{sorted(_CREATE_TRANSIENT)} then Active are legal"
    )

    # --- The description must echo the request and be fully populated.
    assert desc.get("Type") == "MicrosoftAD", (
        f"Type must echo the created directory type MicrosoftAD, got {desc.get('Type')!r}"
    )
    assert desc.get("Edition") == "Standard", (
        f"Edition must echo the request -- and it must be the CHEAP one, never Enterprise, got "
        f"{desc.get('Edition')!r}"
    )
    # Real AWS reports Size alongside Edition for a MicrosoftAD even though CreateMicrosoftAD takes
    # no Size parameter at all, so this is a derived field, not an echo. Measured: "Small".
    assert desc.get("Size") == "Small", (
        f"a Standard MicrosoftAD also reports the derived Size 'Small', got {desc.get('Size')!r}"
    )
    assert desc.get("Name") == fqdn, f"Name must echo the request, got {desc.get('Name')!r}"
    assert desc.get("ShortName") == "SIM2REAL", (
        f"ShortName must echo the request, got {desc.get('ShortName')!r}"
    )
    assert desc.get("SsoEnabled") is False, (
        f"SsoEnabled must default to False (this check never calls EnableSso), got "
        f"{desc.get('SsoEnabled')!r}"
    )
    assert desc.get("Alias") == directory_id, (
        f"with no alias created, Alias defaults to the DirectoryId, got {desc.get('Alias')!r}"
    )
    access_url = desc.get("AccessUrl") or ""
    assert re.fullmatch(r"[A-Za-z0-9.-]+(:\d+)?", access_url), (
        f"AccessUrl is not a well-formed host: {access_url!r}"
    )
    assert access_url.split(".", 1)[0] == directory_id, (
        f"the application access URL is derived from the alias, so with no alias created it must "
        f"lead with {directory_id!r}, got {access_url!r}"
    )
    assert desc.get("LaunchTime") is not None, "LaunchTime must be populated once Active"
    assert desc.get("StageLastUpdatedDateTime") is not None, (
        "StageLastUpdatedDateTime must be populated once the stage has moved"
    )
    assert desc["StageLastUpdatedDateTime"] >= desc["LaunchTime"], (
        f"the stage cannot have last changed before the directory launched: "
        f"StageLastUpdatedDateTime={desc['StageLastUpdatedDateTime']} < "
        f"LaunchTime={desc['LaunchTime']}"
    )
    assert desc.get("DesiredNumberOfDomainControllers") == 2, (
        f"a Managed Microsoft AD is provisioned with two domain controllers and nothing here calls "
        f"UpdateNumberOfDomainControllers, got "
        f"{desc.get('DesiredNumberOfDomainControllers')!r}"
    )
    assert desc.get("OsVersion"), (
        f"a MicrosoftAD runs on a concrete Windows Server version and must report it, got "
        f"{desc.get('OsVersion')!r}"
    )
    regions_info = desc.get("RegionsInfo") or {}
    assert regions_info.get("PrimaryRegion") == ctx.region, (
        f"the primary region must be the region the directory was created in ({ctx.region}), got "
        f"{regions_info.get('PrimaryRegion')!r}"
    )
    assert not regions_info.get("AdditionalRegions"), (
        f"nothing here calls AddRegion, so there must be no replicated regions, got "
        f"{regions_info.get('AdditionalRegions')!r}"
    )
    assert desc.get("NetworkType") == "IPv4", (
        f"the VPC substrate built above is IPv4-only, got NetworkType={desc.get('NetworkType')!r}"
    )
    assert not desc.get("DnsIpv6Addrs"), (
        f"an IPv4 directory must report no IPv6 DNS addresses, got {desc.get('DnsIpv6Addrs')!r}"
    )
    assert "Password" not in desc and "Password" not in str(desc.get("Description") or ""), (
        f"the directory description must never carry the password back: {desc}"
    )

    vpc_settings = desc.get("VpcSettings") or {}
    assert vpc_settings.get("VpcId") == vpc_id, (
        f"VpcSettings.VpcId must be our VPC {vpc_id}, got {vpc_settings.get('VpcId')!r}"
    )
    assert set(vpc_settings.get("SubnetIds") or []) == set(subnet_ids), (
        f"VpcSettings.SubnetIds must be our subnets {subnet_ids}, got "
        f"{vpc_settings.get('SubnetIds')}"
    )
    assert set(vpc_settings.get("AvailabilityZones") or []) == set(subnet_az.values()), (
        f"AvailabilityZones must be the two zones our subnets are in "
        f"{sorted(set(subnet_az.values()))}, got {vpc_settings.get('AvailabilityZones')}"
    )
    assert len(set(vpc_settings.get("AvailabilityZones") or [])) == 2, (
        f"a directory is Multi-AZ by requirement, so exactly two distinct zones must be "
        f"reported, got {vpc_settings.get('AvailabilityZones')}"
    )
    security_group_id = vpc_settings.get("SecurityGroupId") or ""
    assert security_group_id.startswith("sg-"), (
        f"ds must mint a security group for the directory, got {security_group_id!r}"
    )

    # --- The DNS addresses must be real addresses of real ENIs in our subnets. This is the
    # assertion an emulator that only bookkeeps cannot fake.
    dns_addrs = desc.get("DnsIpAddrs") or []
    assert len(dns_addrs) == 2, (
        f"a directory with two domain controllers must report two DnsIpAddrs, got {dns_addrs}"
    )
    network = ipaddress.ip_network(_VPC_CIDR)
    for addr in dns_addrs:
        assert ipaddress.ip_address(addr) in network, (
            f"DnsIpAddr {addr} is outside the directory's own VPC CIDR {_VPC_CIDR}"
        )
    enis = ec2.describe_network_interfaces(
        Filters=[{"Name": "subnet-id", "Values": subnet_ids}]
    )["NetworkInterfaces"]
    # Only the ENIs ds itself created for THIS directory count. Filtering by description rather
    # than merely by subnet is what makes the next assertion evidence about the directory instead
    # of evidence that something is in the subnet.
    own_enis = [
        eni
        for eni in enis
        if eni.get("Description") == f"AWS created network interface for directory {directory_id}"
    ]
    assert len(own_enis) == 2, (
        f"ds must create exactly two ENIs for {directory_id}, described 'AWS created network "
        f"interface for directory {directory_id}', found {len(own_enis)} of "
        f"{[(e.get('NetworkInterfaceId'), e.get('Description')) for e in enis]}"
    )
    assert {eni.get("SubnetId") for eni in own_enis} == set(subnet_ids), (
        f"the two domain-controller ENIs must be one per subnet across {subnet_ids}, got "
        f"{[(e.get('NetworkInterfaceId'), e.get('SubnetId')) for e in own_enis]}"
    )
    eni_addrs = {eni.get("PrivateIpAddress") for eni in own_enis}
    assert set(dns_addrs) == eni_addrs, (
        f"the directory's DnsIpAddrs {sorted(dns_addrs)} must be exactly the private addresses of "
        f"its own two ENIs, which are {sorted(a for a in eni_addrs if a)}"
    )
    for eni in own_enis:
        assert security_group_id in {
            g.get("GroupId") for g in eni.get("Groups") or []
        }, (
            f"ENI {eni.get('NetworkInterfaceId')} must be in the directory's own security group "
            f"{security_group_id}, got {eni.get('Groups')}"
        )

    # --- The security group ds minted lives in our VPC, is named after the directory, and confines
    # the domain-controller ports to the VPC rather than exposing them.
    groups = ec2.describe_security_groups(GroupIds=[security_group_id])["SecurityGroups"]
    assert groups and groups[0].get("VpcId") == vpc_id, (
        f"the directory's security group {security_group_id} must live in {vpc_id}, got {groups}"
    )
    group = groups[0]
    assert group.get("GroupName") == f"{directory_id}_controllers", (
        f"ds names the group it mints after the directory it serves, expected "
        f"{directory_id}_controllers, got {group.get('GroupName')!r}"
    )
    permissions = group.get("IpPermissions") or []
    assert permissions, (
        f"the domain controllers must be reachable, so the group must carry ingress rules: {group}"
    )
    exposed = [
        rule
        for rule in permissions
        for cidr in (rule.get("IpRanges") or [])
        if cidr.get("CidrIp") not in (_VPC_CIDR,)
    ]
    assert not exposed, (
        f"every ingress rule must be scoped to the directory's own VPC CIDR {_VPC_CIDR} -- a "
        f"directory must never be reachable from outside it -- but found {exposed}"
    )

    # --- Delete, and drive to gone.
    ds.delete_directory(DirectoryId=directory_id)
    gone = _poll(
        lambda: _describe(ds, directory_id),
        lambda d: d is None,
        timeout_s=2400.0,
        interval_s=30.0,
    )
    assert gone is None, (
        f"DeleteDirectory must drive {directory_id} to gone, it is still "
        f"{(gone or {}).get('Stage')!r}"
    )

    # --- Gone is not one uniform answer. DescribeDirectories does NOT refuse a deleted id: it
    # succeeds with an EMPTY DirectoryDescriptions list. It refuses only an id it never issued,
    # with a DIFFERENT message under the same error code. Asserting both halves catches an
    # emulator that raises for every unknown id and one that returns empty for every unknown id.
    after_read = ds.describe_directories(DirectoryIds=[directory_id])
    assert after_read.get("DirectoryDescriptions") == [], (
        f"DescribeDirectories on the deleted {directory_id} must succeed with an EMPTY "
        f"DirectoryDescriptions list, got {after_read.get('DirectoryDescriptions')!r}"
    )
    never_issued = _absent_directory_id(ds)
    unknown = _error(lambda: ds.describe_directories(DirectoryIds=[never_issued]))
    assert unknown.get("Code") == "EntityDoesNotExistException", (
        f"DescribeDirectories must still REJECT a well-formed id this account was never issued "
        f"({never_issued}) -- that is what proves the empty result above is specific to a "
        f"directory that really existed here, not blanket tolerance -- got {unknown!r}"
    )
    assert "Invalid directory ID" in (unknown.get("Message") or ""), (
        f"the never-issued id must be reported as an invalid directory ID, which is how ds "
        f"distinguishes it from one it deleted, got {unknown.get('Message')!r}"
    )
    expected_message = f"Invalid directory ID(s): {never_issued}. : RequestId: {unknown.get('RequestId')}"
    assert unknown.get("Message") == expected_message, (
        f"expected {expected_message!r}, got {unknown.get('Message')!r}"
    )

    # The tolerance belongs to DescribeDirectories alone. Every operation that has to resolve the
    # id to a LIVE directory refuses the deleted one outright -- and, unlike DescribeDirectories,
    # phrases it as "does not exist" rather than "invalid".
    repeat_delete = _error(lambda: ds.delete_directory(DirectoryId=directory_id))
    assert repeat_delete.get("Code") == "EntityDoesNotExistException", (
        f"a second DeleteDirectory must raise EntityDoesNotExistException (the only not-found "
        f"error it declares), not succeed idempotently, got {repeat_delete!r}"
    )
    assert f"Directory: '{directory_id}' does not exist." in (
        repeat_delete.get("Message") or ""
    ), (
        f"DeleteDirectory must name the missing directory as nonexistent, got "
        f"{repeat_delete.get('Message')!r}"
    )
    expected_message = f"Directory: '{directory_id}' does not exist. : RequestId: {repeat_delete.get('RequestId')}"
    assert repeat_delete.get("Message") == expected_message, (
        f"expected {expected_message!r}, got {repeat_delete.get('Message')!r}"
    )
    limits = _error(lambda: ds.get_snapshot_limits(DirectoryId=directory_id))
    assert limits.get("Code") == "EntityDoesNotExistException", (
        f"GetSnapshotLimits on the deleted {directory_id} must raise EntityDoesNotExistException "
        f"-- a read that must resolve a live directory does NOT get DescribeDirectories' empty "
        f"result -- got {limits!r}"
    )
    expected_message = f"Directory: '{directory_id}' does not exist. : RequestId: {limits.get('RequestId')}"
    assert limits.get("Message") == expected_message, (
        f"expected {expected_message!r}, got {limits.get('Message')!r}"
    )
    assert directory_id not in {
        d.get("DirectoryId")
        for d in ds.describe_directories().get("DirectoryDescriptions", [])
    }, f"{directory_id} is still in the unfiltered inventory after deletion"

    # --- Deletion must release the ENIs, or the subnets and VPC could never be deleted. This is
    # also what makes this check's own cleanup safe.
    remaining = ec2.describe_network_interfaces(
        Filters=[{"Name": "subnet-id", "Values": subnet_ids}]
    )["NetworkInterfaces"]
    assert not remaining, (
        f"DeleteDirectory must release the directory's ENIs, still present: "
        f"{[eni.get('NetworkInterfaceId') for eni in remaining]}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
