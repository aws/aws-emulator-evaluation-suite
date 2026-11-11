"""valid-db-instance-modifications-bound-what-modify-accepts."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "valid-db-instance-modifications-bound-what-modify-accepts"
GROUP = "server-side"
SERVICES = ["rds"]

_DB = "simparitydb"
_USER = "sim2real"
_PASS = "Sim2Real#Pass99"
_START_STORAGE = 20
_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
    {"Key": "sim2real", "Value": "valid-db-instance-modifications"},
]


# ===== helpers =====
def _poll_until(probe, pred, *, timeout_s, interval_s, description):
    """Poll probe() until pred(value); RAISE on the deadline, never return the last value."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if pred(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} was not observed within {timeout_s}s; last saw {last!r}"
            )
        time.sleep(interval_s)


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, so a target that
    ACCEPTS input real AWS refuses fails as an acceptance, not as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


#: Codes AWS answers while a dependency of the resource is still being released.
_BUSY_CODES = (
    "DependencyViolation", "DeleteConflict", "InvalidDBInstanceState",
    "InvalidDBSubnetGroupStateFault", "InvalidDBSubnetGroupState",
)


def _retry_delete(fn, *tolerated_codes, timeout_s=900, interval_s=2, what=""):
    """Delete something: done on its not-found codes, retried while a dependency still holds it
    (_BUSY_CODES) to the deadline, and every other error raised."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in tolerated_codes:
                return
            if code not in _BUSY_CODES:
                raise
            if time.monotonic() >= deadline:
                raise RuntimeError(f"{what or fn!r} not deleted, last error {code!r}") from exc
        time.sleep(interval_s)


def _network(ctx):
    """A dedicated VPC with subnets in two AZs and a DB subnet group, built rather than discovered
    because the account may have no default VPC. No internet gateway: nothing connects to the DB."""
    ec2 = ctx.client("ec2")
    rds = ctx.client("rds")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.176.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _TAGS}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(
        lambda: _retry_delete(
            lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id), "InvalidVpcID.NotFound", what=f"vpc {vpc_id}"
        )
    )
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    zones = ec2.describe_availability_zones(
        Filters=[
            {"Name": "state", "Values": ["available"]},
            {"Name": "opt-in-status", "Values": ["opt-in-not-required"]},
        ]
    )["AvailabilityZones"]
    azs = sorted(z["ZoneName"] for z in zones)
    assert len(azs) >= 2, (
        f"a DB subnet group needs subnets in at least 2 availability zones; {ctx.region} offered "
        f"{azs!r}"
    )

    subnet_ids = []
    for index, az in enumerate(azs[:2]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.176.{index}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _TAGS}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(
            lambda s=subnet_id: _retry_delete(
                lambda: _delete_net(ec2, "delete_subnet", SubnetId=s),
                "InvalidSubnetID.NotFound",
                what=f"subnet {s}",
            )
        )
        subnet_ids.append(subnet_id)

    group_name = ctx.unique_name("sim2real-behav-subnets-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=group_name,
        DBSubnetGroupDescription="sim2real valid-modifications subnets",
        SubnetIds=subnet_ids,
        Tags=_TAGS,
    )
    ctx.on_cleanup(
        lambda: _retry_delete(
            lambda: rds.delete_db_subnet_group(DBSubnetGroupName=group_name),
            "DBSubnetGroupNotFoundFault",
            what=f"db subnet group {group_name}",
        )
    )
    return group_name


def _instance(rds, inst_id):
    try:
        return rds.describe_db_instances(DBInstanceIdentifier=inst_id)["DBInstances"][0]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "DBInstanceNotFound":
            return None
        raise


def _delete_instance(rds, inst_id):
    _retry_delete(
        lambda: rds.delete_db_instance(
            DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True
        ),
        "DBInstanceNotFound",
        what=f"db instance {inst_id}",
    )
    _poll_until(
        lambda: _instance(rds, inst_id),
        lambda i: i is None,
        timeout_s=900,
        interval_s=2,
        description=f"db instance {inst_id} disappearing so its VPC can be torn down",
    )


def _wait_available(rds, inst_id, *, timeout_s=2400):
    return _poll_until(
        lambda: _instance(rds, inst_id),
        lambda i: i is not None and i.get("DBInstanceStatus") == "available",
        timeout_s=timeout_s,
        interval_s=20,
        description=f"db instance {inst_id} returning to 'available'",
    )


def _default_engine_version(rds, engine):
    versions = rds.describe_db_engine_versions(Engine=engine, DefaultOnly=True).get(
        "DBEngineVersions", []
    )
    assert versions, f"no default {engine!r} engine version is orderable in {rds.meta.region_name}"
    return versions[0]


def _orderable_class(rds, engine, version):
    classes = set()
    for page in rds.get_paginator("describe_orderable_db_instance_options").paginate(
        Engine=engine, EngineVersion=version
    ):
        for opt in page.get("OrderableDBInstanceOptions", []):
            classes.add(opt["DBInstanceClass"])
    for want in ("db.t4g.micro", "db.t3.micro", "db.t4g.small", "db.t3.small"):
        if want in classes:
            return want
    raise AssertionError(
        f"no small orderable instance class for {engine} {version}; offered {sorted(classes)!r}"
    )


def _storage_option(rds, inst_id, storage_type):
    """The ValidStorageOptions entry the instance reports for its own current StorageType."""
    reported = rds.describe_valid_db_instance_modifications(DBInstanceIdentifier=inst_id)[
        "ValidDBInstanceModificationsMessage"
    ]
    options = reported.get("Storage") or []
    assert options, (
        f"DescribeValidDBInstanceModifications must report at least one Storage option for "
        f"{inst_id}; it returned {reported!r}"
    )
    for option in options:
        if option.get("StorageType") == storage_type:
            return option
    raise AssertionError(
        f"DescribeValidDBInstanceModifications must describe the instance's OWN storage type "
        f"{storage_type!r}: it reported only "
        f"{sorted(o.get('StorageType') for o in options)!r}"
    )


def _containing_range(option, value):
    """The reported StorageSize Range that brackets `value`, hard-failing when none does."""
    ranges = option.get("StorageSize") or []
    assert ranges, (
        f"the reported storage option for {option.get('StorageType')!r} carries no StorageSize "
        f"range: {option!r}"
    )
    for entry in ranges:
        if entry.get("From") is not None and entry.get("To") is not None:
            if entry["From"] <= value <= entry["To"]:
                return entry
    raise AssertionError(
        f"the instance's own current AllocatedStorage {value} must fall inside one of the "
        f"StorageSize ranges the instance reports: it reported "
        f"{[(r.get('From'), r.get('To'), r.get('Step')) for r in ranges]!r}"
    )


def _growth_floor(option, value):
    """The lowest StorageSize range strictly above `value`: the smallest enlargement RDS accepts.

    RDS reports disjoint ranges; the gap above the current allocation is its minimum-increase rule.
    """
    ranges = option.get("StorageSize") or []
    above = [r for r in ranges if r.get("From") is not None and r["From"] > value]
    assert above, (
        f"DescribeValidDBInstanceModifications must report at least one StorageSize range "
        f"enlarging beyond the current allocation {value}; it reported only "
        f"{[(r.get('From'), r.get('To'), r.get('Step')) for r in ranges]!r}"
    )
    return min(above, key=lambda r: r["From"])


def _allocated(rds, inst_id):
    inst = _instance(rds, inst_id)
    assert inst is not None, f"db instance {inst_id} vanished while reading AllocatedStorage"
    return inst["AllocatedStorage"]
# ===== end helpers =====


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyDBInstance refuses AllocatedStorage past the reported ceiling or in the reported gap,
    applies the growth range's floor, and the reported growth floor then sits above the new size.

    Reference: https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeValidDBInstanceModifications.html
    """
    rds = ctx.client("rds")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    assert account_id.isdigit(), f"caller account id is not numeric: {account_id!r}"

    engine = "postgres"
    version = _default_engine_version(rds, engine)["EngineVersion"]
    klass = _orderable_class(rds, engine, version)
    subnet_group = _network(ctx)

    inst_id = ctx.unique_name("sim2real-behav-inst-")
    rds.create_db_instance(
        DBInstanceIdentifier=inst_id,
        Engine=engine,
        EngineVersion=version,
        DBInstanceClass=klass,
        AllocatedStorage=_START_STORAGE,
        MasterUsername=_USER,
        MasterUserPassword=_PASS,
        DBName=_DB,
        DBSubnetGroupName=subnet_group,
        BackupRetentionPeriod=0,
        PubliclyAccessible=False,
        DeletionProtection=False,
        Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, inst_id))

    inst = _wait_available(rds, inst_id)
    storage_type = inst.get("StorageType")
    assert storage_type, (
        f"DescribeDBInstances must report a StorageType for {inst_id} — it is the key the valid "
        f"modifications document is looked up by; got {inst!r}"
    )
    allocated = inst["AllocatedStorage"]
    assert allocated == _START_STORAGE, (
        f"expected the instance to start at {_START_STORAGE} GiB; DescribeDBInstances reports "
        f"{allocated}"
    )

    option = _storage_option(rds, inst_id, storage_type)
    window = _containing_range(option, allocated)
    floor_range = _growth_floor(option, allocated)
    ranges = option.get("StorageSize") or []
    ceiling_range = max((r for r in ranges if r.get("To") is not None), key=lambda r: r["To"])
    ceiling = ceiling_range["To"]
    ceiling_step = ceiling_range.get("Step") or 1
    assert floor_range["From"] > allocated, (
        f"the growth range DescribeValidDBInstanceModifications reports must start strictly above "
        f"the current allocation {allocated}; it reported {floor_range!r}"
    )

    # The highest StorageSize.To across every range, not just the range bracketing the current value.
    too_big = ceiling + ceiling_step
    error = _client_error(
        lambda: rds.modify_db_instance(
            DBInstanceIdentifier=inst_id, AllocatedStorage=too_big, ApplyImmediately=True
        )
    )
    assert error.get("Code") == "InvalidParameterCombination", (
        f"AllocatedStorage={too_big} is one Step ({ceiling_step}) past the ceiling {ceiling} that "
        f"DescribeValidDBInstanceModifications reported for {storage_type!r} on this very instance, "
        f"so it must be refused with InvalidParameterCombination; got {error.get('Code')!r} / "
        f"{error.get('Message')!r}"
    )
    expected = f"Invalid storage size for engine name {engine} and storage type {storage_type}: {too_big}"
    assert error.get("Message") == expected, (
        f"the ceiling refusal must carry RDS's exact message {expected!r}; got {error.get('Message')!r}"
    )

    after_refusal = _instance(rds, inst_id)
    assert after_refusal is not None and after_refusal["AllocatedStorage"] == allocated, (
        f"the refused modify must leave AllocatedStorage at {allocated}; DescribeDBInstances now "
        f"reports {after_refusal and after_refusal.get('AllocatedStorage')!r}"
    )
    pending = (after_refusal.get("PendingModifiedValues") or {}).get("AllocatedStorage")
    assert pending is None, (
        f"the refused modify must not be QUEUED either: PendingModifiedValues.AllocatedStorage is "
        f"{pending!r} on {inst_id}"
    )

    # RDS reports the current-allocation range and the growth range as disjoint; a value in the
    # gap is refused. Only probed when the reported document actually has a gap.
    gap_step = window.get("Step") or 1
    gap_probe = allocated + gap_step
    if gap_probe < floor_range["From"]:
        gap_error = _client_error(
            lambda: rds.modify_db_instance(
                DBInstanceIdentifier=inst_id, AllocatedStorage=gap_probe, ApplyImmediately=True
            )
        )
        assert gap_error.get("Code") == "InvalidParameterCombination", (
            f"AllocatedStorage={gap_probe} falls in the GAP DescribeValidDBInstanceModifications "
            f"itself reports between the current-allocation range (up to {window['To']}) and the "
            f"growth range (from {floor_range['From']}), so it must be refused with "
            f"InvalidParameterCombination; got {gap_error.get('Code')!r} / "
            f"{gap_error.get('Message')!r}"
        )
        gap_expected = (
            f"Invalid storage size for engine name {engine} and storage type {storage_type}: {gap_probe}"
        )
        assert gap_error.get("Message") == gap_expected, (
            f"the gap refusal must carry RDS's exact message {gap_expected!r}; got "
            f"{gap_error.get('Message')!r}"
        )
        gap_after = _instance(rds, inst_id)
        assert gap_after is not None and gap_after["AllocatedStorage"] == allocated, (
            f"the gap-value refusal must leave AllocatedStorage at {allocated}; DescribeDBInstances "
            f"now reports {gap_after and gap_after.get('AllocatedStorage')!r}"
        )

    grown = floor_range["From"]
    assert floor_range["From"] <= grown <= floor_range["To"], (
        f"the positive control must stay inside the growth range the instance reported "
        f"({floor_range['From']}..{floor_range['To']} step {floor_range.get('Step')}): got {grown}"
    )
    rds.modify_db_instance(
        DBInstanceIdentifier=inst_id, AllocatedStorage=grown, ApplyImmediately=True
    )
    # A storage modification passes through 'storage-optimization' and can outlast the create.
    _poll_until(
        lambda: _allocated(rds, inst_id),
        lambda value: value == grown,
        timeout_s=2400,
        interval_s=30,
        description=(
            f"AllocatedStorage on {inst_id} reaching the in-range value {grown} — the positive "
            f"control without which the refusal above proves nothing"
        ),
    )
    settled = _wait_available(rds, inst_id)
    assert settled["AllocatedStorage"] == grown, (
        f"expected AllocatedStorage {grown} after the accepted modify settled; DescribeDBInstances "
        f"reports {settled['AllocatedStorage']}"
    )

    # The range bracketing the current value always reports From == To == current, so only the
    # growth range's floor shows the document tracks live state.
    regrown = _storage_option(rds, inst_id, settled.get("StorageType") or storage_type)
    regrown_floor = _growth_floor(regrown, grown)
    assert regrown_floor["From"] > grown, (
        f"RDS does not permit a storage DECREASE, so after growing to {grown} GiB the growth "
        f"range's own floor must sit strictly above {grown}; it reports {regrown_floor!r} (before "
        f"the growth, the floor above {allocated} was {floor_range['From']})"
    )
    shrink = _client_error(
        lambda: rds.modify_db_instance(
            DBInstanceIdentifier=inst_id, AllocatedStorage=allocated, ApplyImmediately=True
        )
    )
    assert shrink.get("Code") == "InvalidParameterCombination", (
        f"a shrink back to {allocated} GiB is now below the floor the instance itself reports, so "
        f"it must be refused; got {shrink.get('Code')!r} / {shrink.get('Message')!r}"
    )
    shrink_expected = (
        f"Invalid storage size for engine name {engine} and storage type {storage_type}: {allocated}"
    )
    assert shrink.get("Message") == shrink_expected, (
        f"the shrink refusal must carry RDS's exact message {shrink_expected!r}; got "
        f"{shrink.get('Message')!r}"
    )
    assert _allocated(rds, inst_id) == grown, (
        f"the refused shrink must leave AllocatedStorage at {grown}"
    )


# AWS-managed ENIs of resources in the VPC are released asynchronously after their delete returns,
# so network deletes wait (bounded) for them and retry DependencyViolation within one shared window.
_NET_TEARDOWN_S = 1260.0
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
