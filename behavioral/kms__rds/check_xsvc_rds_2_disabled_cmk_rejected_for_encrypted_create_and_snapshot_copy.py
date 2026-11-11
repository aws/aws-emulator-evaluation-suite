"""xsvc-rds-2-disabled-cmk-rejected-for-encrypted-create-and-snapshot-copy."""

from __future__ import annotations

import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-rds-2-disabled-cmk-rejected-for-encrypted-create-and-snapshot-copy"
GROUP = "kms-key-state-enforcement"
SERVICES = ["kms", "rds"]

_SCENARIO = "rds-disabled-cmk-encryption"
_USER = "sim2real"
_TAGS = [
    {"Key": "sim2real", "Value": _SCENARIO},
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-xsvc"},
]
#: RDS refuses encryption under a disabled CMK with this code (HTTP 400); terminal, never retried.
_KMS_FAULT = "KMSKeyNotAccessibleFault"
#: What _call reports for a call that SUCCEEDED: a value no error code can equal.
_ACCEPTED = "<call succeeded>"


@tags(
    "axis:rejection",
    "concern:e2e",
    "concern:negative-classes",
    "plane:control",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """Under a disabled CMK, encrypted CreateDBInstance and CopyDBSnapshot fail with
    KMSKeyNotAccessibleFault (HTTP 400) and leave nothing behind; after EnableKey the same calls
    succeed and the copied snapshot is encrypted under that key.

    Reference: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.Keys.html
    """
    kms = ctx.client("kms")
    rds = ctx.client("rds")
    ec2 = ctx.client("ec2")

    key = kms.create_key(
        Description="sim2real xsvc check: disabled CMK gates RDS storage encryption",
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=[{"TagKey": t["Key"], "TagValue": t["Value"]} for t in _TAGS],
    )["KeyMetadata"]
    key_id, key_arn = key["KeyId"], key["Arn"]
    ctx.on_cleanup(lambda: _schedule_key_deletion(kms, key_id))
    # Re-enable before anything encrypted under the key is torn down (LIFO: runs after them).
    ctx.on_cleanup(lambda: _enable_key(kms, key_id))

    subnet_group = _network(ctx, ec2, rds)
    engine = "postgres"
    version = _default_engine_version(rds, engine)
    klass = _orderable_class(rds, engine, version)
    common = dict(
        Engine=engine,
        EngineVersion=version,
        DBInstanceClass=klass,
        AllocatedStorage=20,
        MasterUsername=_USER,
        MasterUserPassword=secrets.token_hex(16),
        BackupRetentionPeriod=0,
        DBSubnetGroupName=subnet_group,
        PubliclyAccessible=False,
        DeletionProtection=False,
        Tags=_TAGS,
    )

    # An unencrypted copy source, so the only key on the copy path is the target CMK.
    src_id = ctx.unique_name("sim2real-xsvc-src-")
    rds.create_db_instance(DBInstanceIdentifier=src_id, StorageEncrypted=False, **common)
    ctx.on_cleanup(lambda: _delete_instance(rds, src_id, wait_s=1200, raise_on_leak=True))
    _wait_instance_available(rds, src_id, timeout_s=_budget_s(ctx, 1080), ctx=ctx)

    snap_id = ctx.unique_name("sim2real-xsvc-snap-")
    rds.create_db_snapshot(DBSnapshotIdentifier=snap_id, DBInstanceIdentifier=src_id, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_snapshot(rds, snap_id))
    source = _wait_snapshot_available(rds, snap_id, timeout_s=_budget_s(ctx, 1200), ctx=ctx)
    assert source["Encrypted"] is False, (
        f"the copy source must be unencrypted so only the target CMK is in play; got {source!r}"
    )
    # The snapshot is all the copy path needs; stop paying for the instance now.
    _delete_instance(rds, src_id)

    # The one broken thing: disable the CMK, polled to the observable state.
    kms.disable_key(KeyId=key_id)
    _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"],
        lambda s: s == "Disabled",
        timeout_s=_budget_s(ctx, 60), interval_s=2, description=f"CMK {key_id} to report KeyState=Disabled",
        ctx=ctx,
    )

    inst_id = ctx.unique_name("sim2real-xsvc-enc-")
    create_args = dict(DBInstanceIdentifier=inst_id, StorageEncrypted=True, KmsKeyId=key_arn,
                       **common)
    code, status, msg, result = _call(lambda: rds.create_db_instance(**create_args))
    if code == _ACCEPTED:
        # The target wrongly ACCEPTED it: the instance exists, so reap it before failing.
        ctx.on_cleanup(lambda: _delete_instance(rds, inst_id, wait_s=1200, raise_on_leak=True))
    assert code == _KMS_FAULT, (
        f"CreateDBInstance(StorageEncrypted=True) under a DISABLED CMK must be refused with "
        f"{_KMS_FAULT}; got code={code!r} status={status!r} message={msg!r} result={result!r}"
    )
    assert msg == f"The specified KMS key [{key['Arn']}] does not exist, is not enabled or you do not have permissions to access it.", (
        f"expected the exact KMSKeyNotAccessibleFault message AWS returns, got {msg!r}"
    )
    assert status == 400, f"{_KMS_FAULT} on CreateDBInstance must be HTTP 400, got {status!r}"
    create_msg = msg
    gone_code, _, gone_msg, gone_result = _call(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=inst_id)
    )
    assert gone_code == "DBInstanceNotFound", (
        f"a CreateDBInstance refused for the key must leave NO instance behind; "
        f"DescribeDBInstances returned code={gone_code!r} {gone_msg!r} {gone_result!r}"
    )
    assert gone_msg == f"DBInstance {create_args['DBInstanceIdentifier']} not found.", (
        f"expected the exact DBInstanceNotFound message AWS returns, got {gone_msg!r}"
    )
    instance_gone_msg = gone_msg

    copy_id = ctx.unique_name("sim2real-xsvc-copy-")
    copy_args = dict(SourceDBSnapshotIdentifier=snap_id, TargetDBSnapshotIdentifier=copy_id,
                     KmsKeyId=key_arn, Tags=_TAGS)
    code, status, msg, result = _call(lambda: rds.copy_db_snapshot(**copy_args))
    if code == _ACCEPTED:
        ctx.on_cleanup(lambda: _delete_snapshot(rds, copy_id))
    assert code == _KMS_FAULT, (
        f"CopyDBSnapshot(KmsKeyId=<disabled CMK>) must be refused with {_KMS_FAULT}; got "
        f"code={code!r} status={status!r} message={msg!r} result={result!r}"
    )
    assert msg == f"The target KMS key [{key['Arn']}] does not exist, is not enabled or you do not have permissions to access it.", (
        f"expected the exact KMSKeyNotAccessibleFault message AWS returns, got {msg!r}"
    )
    assert status == 400, f"{_KMS_FAULT} on CopyDBSnapshot must be HTTP 400, got {status!r}"
    gone_code, _, gone_msg, gone_result = _call(
        lambda: rds.describe_db_snapshots(DBSnapshotIdentifier=copy_id)
    )
    assert gone_code == "DBSnapshotNotFound", (
        f"a CopyDBSnapshot refused for the key must leave NO target snapshot; "
        f"DescribeDBSnapshots returned code={gone_code!r} {gone_msg!r} {gone_result!r}"
    )
    assert gone_msg == f"DBSnapshot not found: {copy_args['TargetDBSnapshotIdentifier']}", (
        f"expected the exact DBSnapshotNotFound message AWS returns, got {gone_msg!r}"
    )
    # Every refusal's exact message, built from the identifiers this check chose.
    messages = {
        "CreateDBInstance": create_msg,
        "DescribeDBInstances": instance_gone_msg,
        "CopyDBSnapshot": msg,
        "DescribeDBSnapshots": gone_msg,
    }
    expected_messages = {
        "CreateDBInstance": (
            f"The specified KMS key [{key_arn}] does not exist, is not enabled or you do not "
            "have permissions to access it."
        ),
        "DescribeDBInstances": f"DBInstance {inst_id} not found.",
        "CopyDBSnapshot": (
            f"The target KMS key [{key_arn}] does not exist, is not enabled or you do not "
            "have permissions to access it."
        ),
        "DescribeDBSnapshots": f"DBSnapshot not found: {copy_id}",
    }
    wrong = {op: (got, expected_messages[op]) for op, got in messages.items()
             if got != expected_messages[op]}
    assert not wrong, f"refusal messages differ, as (got, expected): {wrong!r}"

    # Positive control on the same wiring: re-enable and repeat the identical calls.
    kms.enable_key(KeyId=key_id)
    _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"],
        lambda s: s == "Enabled",
        timeout_s=_budget_s(ctx, 60), interval_s=2, description=f"CMK {key_id} to report KeyState=Enabled",
        ctx=ctx,
    )

    created = rds.create_db_instance(**create_args)["DBInstance"]
    ctx.on_cleanup(lambda: _delete_instance(rds, inst_id, wait_s=1200, raise_on_leak=True))
    assert created["StorageEncrypted"] is True and created.get("KmsKeyId") == key_arn, (
        f"with the CMK re-enabled the identical CreateDBInstance must be accepted encrypted under "
        f"it; StorageEncrypted={created.get('StorageEncrypted')!r} "
        f"KmsKeyId={created.get('KmsKeyId')!r} (want {key_arn!r})"
    )
    seen = rds.describe_db_instances(DBInstanceIdentifier=inst_id)["DBInstances"][0]
    assert seen.get("KmsKeyId") == key_arn and seen["StorageEncrypted"] is True, (
        f"DescribeDBInstances must report the accepted instance under the CMK: "
        f"{seen.get('KmsKeyId')!r} / {seen.get('StorageEncrypted')!r}"
    )
    # Proven accepted; do not pay for it to reach 'available'.
    _delete_instance(rds, inst_id)

    copied = rds.copy_db_snapshot(**copy_args)["DBSnapshot"]
    ctx.on_cleanup(lambda: _delete_snapshot(rds, copy_id))
    assert copied["DBSnapshotIdentifier"] == copy_id, f"copy returned {copied!r}"
    target = _wait_snapshot_available(rds, copy_id, timeout_s=_budget_s(ctx, 1200), ctx=ctx)
    assert target["Encrypted"] is True and target.get("KmsKeyId") == key_arn, (
        f"the snapshot copied with KmsKeyId=<CMK> must be encrypted under that CMK; "
        f"Encrypted={target.get('Encrypted')!r} KmsKeyId={target.get('KmsKeyId')!r} "
        f"(want {key_arn!r})"
    )
    src_after = rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id)["DBSnapshots"][0]
    assert src_after["Encrypted"] is False, (
        f"copying must not mutate the source snapshot's encryption: {src_after['Encrypted']!r}"
    )

    # Wait here, not only in cleanup: the cleanup chain is bounded at 60 s, and the subnet group
    # cannot be deleted while an instance holds it.
    _delete_instance(rds, inst_id, wait_s=_budget_s(ctx, 1200))
    _delete_instance(rds, src_id, wait_s=_budget_s(ctx, 1200))


def _call(fn):
    """Call fn() once; return (code, http_status, message, result), with code _ACCEPTED on success.
    No retry: KMSKeyNotAccessibleFault is terminal."""
    try:
        return _ACCEPTED, 200, "", fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), status, err.get("Message", ""), exc.response


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s, interval_s, description, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{description}: the run budget ended first; not graded")
            raise AssertionError(f"waited {timeout_s:.0f}s for {description}; last saw {last!r}")
        time.sleep(interval_s)
        last = probe()
    return last


def _network(ctx, ec2, rds):
    """A private VPC with two subnets in two derived AZs and a DB subnet group."""
    tag_spec = lambda kind: [{"ResourceType": kind, "Tags": _TAGS}]  # noqa: E731
    vpc_id = ec2.create_vpc(CidrBlock="10.80.0.0/16", TagSpecifications=tag_spec("vpc"))["Vpc"][
        "VpcId"
    ]
    ctx.on_cleanup(lambda: _retry_delete(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id),
                                         gone="InvalidVpcID.NotFound", what=f"vpc {vpc_id}"))
    zones = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
        if z.get("ZoneType", "availability-zone") == "availability-zone"
    )
    assert len(zones) >= 2, f"a DB subnet group needs two AZs; {ctx.region} offers {zones!r}"
    subnets = []
    for i, zone in enumerate(zones[:2]):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.80.{i}.0/24", AvailabilityZone=zone,
            TagSpecifications=tag_spec("subnet"),
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=sid: _retry_delete(
            lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid), gone="InvalidSubnetID.NotFound",
            what=f"subnet {sid}"))
        subnets.append(sid)
    name = ctx.unique_name("sim2real-xsvc-sng-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name, DBSubnetGroupDescription="sim2real xsvc kms/rds check",
        SubnetIds=subnets, Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name),
        gone="DBSubnetGroupNotFoundFault", what=f"db subnet group {name}"))
    return name


def _retry_delete(fn, *, gone, what, timeout_s=600):
    """ctx.on_cleanup swallows exceptions, so a dependency still draining would leak silently."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == gone:
                return
            if time.monotonic() >= deadline:
                raise RuntimeError(f"could not delete {what}: {exc}") from exc
        time.sleep(2)


def _default_engine_version(rds, engine):
    versions = rds.describe_db_engine_versions(Engine=engine, DefaultOnly=True).get(
        "DBEngineVersions", []
    )
    assert versions, f"no default {engine!r} engine version is orderable in this region"
    return versions[0]["EngineVersion"]


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
    raise AssertionError(f"no small orderable class for {engine} {version}: {sorted(classes)!r}")


def _instance(rds, inst_id):
    try:
        return rds.describe_db_instances(DBInstanceIdentifier=inst_id)["DBInstances"][0]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "DBInstanceNotFound":
            return None
        raise


def _wait_instance_available(rds, inst_id, *, timeout_s=1080, ctx=None):
    inst = _poll_until(
        lambda: _instance(rds, inst_id),
        lambda i: i is None or i.get("DBInstanceStatus") in ("available", "failed"),
        timeout_s=timeout_s, interval_s=2, description=f"DB instance {inst_id} to be available",
        ctx=ctx,
    )
    assert inst is not None, f"DB instance {inst_id} vanished while waiting for 'available'"
    assert inst["DBInstanceStatus"] == "available", (
        f"DB instance {inst_id} ended in {inst['DBInstanceStatus']!r}, not 'available'"
    )
    return inst


def _snapshot(rds, snap_id):
    try:
        return rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id)["DBSnapshots"][0]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "DBSnapshotNotFound":
            return None
        raise


def _wait_snapshot_available(rds, snap_id, *, timeout_s=1200, ctx=None):
    snap = _poll_until(
        lambda: _snapshot(rds, snap_id),
        lambda s: s is None or s.get("Status") in ("available", "failed"),
        timeout_s=timeout_s, interval_s=2, description=f"DB snapshot {snap_id} to be available",
        ctx=ctx,
    )
    assert snap is not None, f"DB snapshot {snap_id} vanished while waiting for 'available'"
    assert snap["Status"] == "available", f"snapshot {snap_id} ended in {snap['Status']!r}"
    return snap


def _delete_instance(rds, inst_id, *, wait_s=0, raise_on_leak=False):
    """Issue the delete (tolerating one already in progress), optionally waiting until it is gone so
    the subnet group can be deleted. A wait that runs out raises only with ``raise_on_leak`` (the
    registered cleanup); an in-run wait leaves the rest to that cleanup."""
    deadline = time.monotonic() + 600
    while True:
        try:
            rds.delete_db_instance(
                DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True
            )
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "DBInstanceNotFound":
                return
            inst = _instance(rds, inst_id)
            if inst is None:
                return
            if inst.get("DBInstanceStatus") == "deleting":
                break
            if time.monotonic() >= deadline:
                raise RuntimeError(f"could not delete DB instance {inst_id}: {exc}") from exc
            time.sleep(2)
    if wait_s:
        end = time.monotonic() + wait_s
        while _instance(rds, inst_id) is not None:
            if time.monotonic() >= end:
                msg = f"DB instance {inst_id} still present {wait_s:.0f}s after delete"
                if raise_on_leak:
                    raise RuntimeError(msg)
                return
            time.sleep(2)


def _delete_snapshot(rds, snap_id):
    deadline = time.monotonic() + 900
    while True:
        try:
            rds.delete_db_snapshot(DBSnapshotIdentifier=snap_id)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "DBSnapshotNotFound":
                return
            if time.monotonic() >= deadline:
                raise RuntimeError(f"could not delete DB snapshot {snap_id}: {exc}") from exc
        time.sleep(2)


def _enable_key(kms, key_id):
    try:
        kms.enable_key(KeyId=key_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "KMSInvalidStateException":
            raise RuntimeError(f"could not re-enable CMK {key_id}: {exc}") from exc


def _schedule_key_deletion(kms, key_id):
    """7 days is the AWS minimum pending window; the key is reported as a leftover."""
    try:
        kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "KMSInvalidStateException":
            raise RuntimeError(f"schedule_key_deletion({key_id}) failed: {exc}") from exc


# Resources in this VPC delete asynchronously and leave ENIs behind for a while, so an immediate
# DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Wait (bounded) for
# the ENIs to go, retry DependencyViolation in the same window, then fail naming the ENIs left.
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
