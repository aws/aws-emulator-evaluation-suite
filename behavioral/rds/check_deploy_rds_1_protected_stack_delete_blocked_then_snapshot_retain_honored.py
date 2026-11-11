"""deploy-rds-1-protected-stack-delete-blocked-then-snapshot-retain-honored."""
from __future__ import annotations

import json
import secrets
import string
import time

from behavioral_harness import tags

CHECK = "deploy-rds-1-protected-stack-delete-blocked-then-snapshot-retain-honored"
GROUP = "deploy-deletion-policy"
SERVICES = ["rds"]

_DB = "Db"
_PG = "Pg"
_USER = "s2radmin"
_MAX_CONNECTIONS = "77"


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c4",
    "concern:deploy",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """Deleting a stack with a DeletionProtection DBInstance ends DELETE_FAILED with the DB intact;
    after protection is lifted the delete succeeds, DeletionPolicy Snapshot leaves a manual snapshot
    and Retain leaves the DBParameterGroup with its template value.
    """
    rds = ctx.client("rds")
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")

    engine_version, family = _default_mysql(rds)
    az_a, az_b = _two_azs(rds, ec2, engine_version)
    password = _password()
    stack_name = ctx.unique_name("sim2real-rds-dp-")

    params = [
        {"ParameterKey": "AzA", "ParameterValue": az_a},
        {"ParameterKey": "AzB", "ParameterValue": az_b},
        {"ParameterKey": "EngineVersion", "ParameterValue": engine_version},
        {"ParameterKey": "Family", "ParameterValue": family},
        {"ParameterKey": "DbPassword", "ParameterValue": password},
    ]
    created = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(_template(protect=True, tag=stack_name)),
        Parameters=params,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    stack_id = created["StackId"]
    # Safety net, registered before any wait: lifts protection, deletes the stack, then reaps the
    # retained parameter group and any final snapshot. Runs LAST (LIFO).
    ctx.on_cleanup(lambda: _teardown_stack(rds, cfn, stack_id))

    stack = _wait_stack(cfn, stack_id, "CREATE_COMPLETE", timeout_s=_budget_s(ctx, 1500), ctx=ctx)

    # NoEcho: the password is never echoed back by DescribeStacks. (Never print the value.)
    echoed = {p["ParameterKey"]: p.get("ParameterValue") for p in stack.get("Parameters", [])}
    assert echoed.get("DbPassword") == "****", (
        f"NoEcho parameter DbPassword was not masked by DescribeStacks "
        f"(got a value of length {len(echoed.get('DbPassword') or '')}, expected '****')"
    )

    resources = _stack_resources(cfn, stack_id)
    instance_id = resources[_DB]["PhysicalResourceId"]
    pg_name = resources[_PG]["PhysicalResourceId"]

    # Cleanup for what the deletion policies will leave behind is registered BEFORE any delete.
    ctx.on_cleanup(lambda: _delete_param_group(rds, pg_name))
    ctx.on_cleanup(lambda: _delete_instance_snapshots(rds, instance_id))

    inst = _describe_instance(rds, instance_id)
    assert inst["DBInstanceStatus"] == "available", (
        f"instance {instance_id!r} status {inst['DBInstanceStatus']!r} after CREATE_COMPLETE"
    )
    assert inst["DeletionProtection"] is True, (
        f"template set DeletionProtection true; instance reports {inst['DeletionProtection']!r}"
    )
    pg_used = [g["DBParameterGroupName"] for g in inst.get("DBParameterGroups", [])]
    assert pg_used == [pg_name], f"instance uses parameter groups {pg_used!r}, expected [{pg_name!r}]"

    # ---- 1. delete while protected: the stack must end DELETE_FAILED and the DB must survive.
    cfn.delete_stack(StackName=stack_id)
    seen_status: set[str] = set()
    failed = _wait_stack(cfn, stack_id, "DELETE_FAILED", timeout_s=_budget_s(ctx, 900), ctx=ctx,
                         on_poll=lambda: seen_status.add(
                             _describe_instance(rds, instance_id)["DBInstanceStatus"]))
    reason = failed.get("StackStatusReason") or ""
    assert reason == f"The following resource(s) failed to delete: [{_DB}]. ", (
        f"StackStatusReason does not name the protected DBInstance [{_DB}]: {reason!r}"
    )
    db_events = [e for e in _stack_events(cfn, stack_id)
                 if e.get("LogicalResourceId") == _DB and e.get("ResourceStatus") == "DELETE_FAILED"]
    assert db_events, f"no DELETE_FAILED stack event for logical resource {_DB!r}"
    assert db_events[0].get("PhysicalResourceId") == instance_id, (
        f"DELETE_FAILED event names {db_events[0].get('PhysicalResourceId')!r}, "
        f"expected {instance_id!r}"
    )
    # message varies: the DBInstance DELETE_FAILED ResourceStatusReason embeds a per-request
    # Request ID and RequestToken, so its stable deletion-protection part is graded.
    db_reason = db_events[0].get("ResourceStatusReason") or ""
    assert "deletion protection" in db_reason.lower(), (
        f"DBInstance DELETE_FAILED reason does not cite deletion protection: {db_reason!r}"
    )
    inst = _describe_instance(rds, instance_id)
    seen_status.add(inst["DBInstanceStatus"])
    assert seen_status == {"available"}, (
        f"protected instance left 'available' during the refused delete: saw {sorted(seen_status)!r}"
    )
    assert inst["DeletionProtection"] is True, "DeletionProtection changed by a refused delete"
    # Dependency order: nothing the instance depends on may have been deleted, and the stack still
    # owns every other resource in CREATE_COMPLETE.
    after = _stack_resources(cfn, stack_id)
    others = {k: v["ResourceStatus"] for k, v in after.items() if k != _DB}
    assert after[_DB]["ResourceStatus"] == "DELETE_FAILED", (
        f"{_DB} resource status {after[_DB]['ResourceStatus']!r}, expected DELETE_FAILED"
    )
    assert set(others.values()) == {"CREATE_COMPLETE"}, (
        f"resources the protected instance depends on changed state during a refused delete: {others!r}"
    )

    # ---- 2. UpdateStack on a DELETE_FAILED stack is a ValidationError ...
    code, msg = _error(lambda: cfn.update_stack(
        StackName=stack_id,
        TemplateBody=json.dumps(_template(protect=False, tag=stack_name)),
        Parameters=[{"ParameterKey": p["ParameterKey"], "UsePreviousValue": True} for p in params],
    ))
    assert code == "ValidationError", f"UpdateStack on a DELETE_FAILED stack returned {code!r}: {msg!r}"
    assert msg == f"Stack:{stack_id} is in DELETE_FAILED state and can not be updated.", (
        f"UpdateStack rejection does not name the state: {msg!r}"
    )
    status_now = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    assert status_now == "DELETE_FAILED", f"rejected UpdateStack moved the stack to {status_now!r}"
    assert _describe_instance(rds, instance_id)["DeletionProtection"] is True, (
        "a rejected UpdateStack lifted DeletionProtection anyway"
    )
    # ... so protection is lifted on the instance itself, as a customer would.
    rds.modify_db_instance(DBInstanceIdentifier=instance_id, DeletionProtection=False,
                           ApplyImmediately=True)
    _wait_instance(rds, instance_id, protect=False, timeout_s=_budget_s(ctx, 600), ctx=ctx)

    # ---- 3. positive control: the same stack now deletes.
    cfn.delete_stack(StackName=stack_id)
    _wait_stack(cfn, stack_id, "DELETE_COMPLETE", timeout_s=_budget_s(ctx, 1500), ctx=ctx)

    # ---- 4. what the deletion policies left behind.
    code, msg = _error(lambda: rds.describe_db_instances(DBInstanceIdentifier=instance_id))
    assert code == "DBInstanceNotFound", (
        f"DescribeDBInstances({instance_id!r}) after DELETE_COMPLETE returned {code!r}: {msg!r}"
    )
    assert msg == f"DBInstance {instance_id} not found.", msg
    snap = _wait_snapshot_available(rds, instance_id, timeout_s=_budget_s(ctx, 600), ctx=ctx)
    assert snap["DBSnapshotIdentifier"].startswith(stack_name), (
        f"DeletionPolicy Snapshot produced {snap['DBSnapshotIdentifier']!r}, "
        f"expected an id starting with the stack name {stack_name!r}"
    )
    assert snap["SnapshotType"] == "manual", f"final snapshot type {snap['SnapshotType']!r}"
    assert snap["Engine"] == "mysql", f"final snapshot engine {snap['Engine']!r}"
    pgs = rds.describe_db_parameter_groups(DBParameterGroupName=pg_name)["DBParameterGroups"]
    assert [g["DBParameterGroupName"] for g in pgs] == [pg_name], (
        f"DeletionPolicy Retain parameter group {pg_name!r} not found after stack delete: {pgs!r}"
    )
    assert pgs[0]["DBParameterGroupFamily"] == family, (
        f"retained group family {pgs[0]['DBParameterGroupFamily']!r}, expected {family!r}"
    )
    user_params = {p["ParameterName"]: p.get("ParameterValue")
                   for page in rds.get_paginator("describe_db_parameters").paginate(
                       DBParameterGroupName=pg_name, Source="user")
                   for p in page["Parameters"]}
    assert user_params.get("max_connections") == _MAX_CONNECTIONS, (
        f"retained group lost the template's max_connections={_MAX_CONNECTIONS}: {user_params!r}"
    )

    # ---- own teardown of the intended artifacts, asserted (the on_cleanup nets stay as backup).
    rds.delete_db_snapshot(DBSnapshotIdentifier=snap["DBSnapshotIdentifier"])
    _wait_gone(lambda: rds.describe_db_snapshots(DBSnapshotIdentifier=snap["DBSnapshotIdentifier"]),
               "DBSnapshotNotFound", f"snapshot {snap['DBSnapshotIdentifier']}", timeout_s=_budget_s(ctx, 600),
               ctx=ctx)
    rds.delete_db_parameter_group(DBParameterGroupName=pg_name)
    _wait_gone(lambda: rds.describe_db_parameter_groups(DBParameterGroupName=pg_name),
               "DBParameterGroupNotFound", f"parameter group {pg_name}", timeout_s=_budget_s(ctx, 120),
               ctx=ctx)



def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _template(protect: bool, tag: str) -> dict:
    tags_ = [{"Key": "sim2real", "Value": tag}]
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "sim2real rds deletion-policy check",
        "Parameters": {
            "AzA": {"Type": "String"},
            "AzB": {"Type": "String"},
            "EngineVersion": {"Type": "String"},
            "Family": {"Type": "String"},
            "DbPassword": {"Type": "String", "NoEcho": True, "MinLength": 12},
        },
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC",
                    "Properties": {"CidrBlock": "10.73.0.0/16", "Tags": tags_}},
            "SubA": {"Type": "AWS::EC2::Subnet",
                     "Properties": {"VpcId": {"Ref": "Vpc"}, "CidrBlock": "10.73.1.0/24",
                                    "AvailabilityZone": {"Ref": "AzA"}, "Tags": tags_}},
            "SubB": {"Type": "AWS::EC2::Subnet",
                     "Properties": {"VpcId": {"Ref": "Vpc"}, "CidrBlock": "10.73.2.0/24",
                                    "AvailabilityZone": {"Ref": "AzB"}, "Tags": tags_}},
            "Sg": {"Type": "AWS::EC2::SecurityGroup",
                   "Properties": {"GroupDescription": "sim2real rds deletion-policy (no ingress)",
                                  "VpcId": {"Ref": "Vpc"}, "Tags": tags_}},
            "SubnetGroup": {"Type": "AWS::RDS::DBSubnetGroup",
                            "Properties": {"DBSubnetGroupDescription": "sim2real deletion-policy",
                                           "SubnetIds": [{"Ref": "SubA"}, {"Ref": "SubB"}],
                                           "Tags": tags_}},
            _PG: {"Type": "AWS::RDS::DBParameterGroup",
                  "DeletionPolicy": "Retain",
                  "UpdateReplacePolicy": "Retain",
                  "Properties": {"Description": "sim2real retained parameter group",
                                 "Family": {"Ref": "Family"},
                                 "Parameters": {"max_connections": _MAX_CONNECTIONS},
                                 "Tags": tags_}},
            _DB: {"Type": "AWS::RDS::DBInstance",
                  "DeletionPolicy": "Snapshot",
                  "UpdateReplacePolicy": "Snapshot",
                  "Properties": {"Engine": "mysql",
                                 "EngineVersion": {"Ref": "EngineVersion"},
                                 "DBInstanceClass": "db.t3.micro",
                                 "AllocatedStorage": "20",
                                 "MasterUsername": _USER,
                                 "MasterUserPassword": {"Ref": "DbPassword"},
                                 "DBSubnetGroupName": {"Ref": "SubnetGroup"},
                                 "VPCSecurityGroups": [{"Ref": "Sg"}],
                                 "DBParameterGroupName": {"Ref": _PG},
                                 "BackupRetentionPeriod": 0,
                                 "MultiAZ": False,
                                 "PubliclyAccessible": False,
                                 "DeletionProtection": protect,
                                 "Tags": tags_}},
        },
    }


def _password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "S2r9" + "".join(secrets.choice(alphabet) for _ in range(20))


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn raises. An unexpected success is an AssertionError,
    never a falsy code."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        err = getattr(exc, "response", {}).get("Error", {})
        if not err:
            raise
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError("call unexpectedly succeeded; real AWS rejects it")


def _default_mysql(rds) -> tuple[str, str]:
    versions = rds.describe_db_engine_versions(Engine="mysql", DefaultOnly=True)["DBEngineVersions"]
    assert versions, "DescribeDBEngineVersions(mysql, DefaultOnly) returned nothing"
    return versions[0]["EngineVersion"], versions[0]["DBParameterGroupFamily"]


def _two_azs(rds, ec2, engine_version: str) -> tuple[str, str]:
    offered: set[str] = set()
    for page in rds.get_paginator("describe_orderable_db_instance_options").paginate(
            Engine="mysql", EngineVersion=engine_version, DBInstanceClass="db.t3.micro", Vpc=True):
        for opt in page["OrderableDBInstanceOptions"]:
            offered.update(a["Name"] for a in opt.get("AvailabilityZones", []))
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert len(usable) >= 2, f"need 2 AZs offering mysql db.t3.micro, usable={usable!r}"
    return usable[0], usable[1]


def _describe_instance(rds, instance_id: str) -> dict:
    return rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]


def _stack_resources(cfn, stack_id: str) -> dict[str, dict]:
    return {r["LogicalResourceId"]: r
            for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]}


def _stack_events(cfn, stack_id: str) -> list[dict]:
    return [e for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id)
            for e in page["StackEvents"]]


def _wait_stack(cfn, stack_id: str, want: str, timeout_s: int, on_poll=None, ctx=None) -> dict:
    deadline = time.monotonic() + timeout_s
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        status = stack["StackStatus"]
        if status == want:
            return stack
        if not status.endswith("_IN_PROGRESS"):
            failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                      for e in _stack_events(cfn, stack_id)[:30] if "FAILED" in e["ResourceStatus"]]
            raise AssertionError(f"stack reached {status!r} while waiting for {want!r}: {failed!r}")
        if time.monotonic() > deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"stack {stack_id} {want!r}: the run budget ended first; not graded")
            raise AssertionError(f"stack still {status!r} after {timeout_s}s waiting for {want!r}")
        if on_poll is not None:
            on_poll()
        time.sleep(2)


def _wait_instance(rds, instance_id: str, protect: bool, timeout_s: int, ctx=None) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        inst = _describe_instance(rds, instance_id)
        if inst["DeletionProtection"] is protect and inst["DBInstanceStatus"] == "available":
            return
        if time.monotonic() > deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(
                    f"instance {instance_id!r} DeletionProtection={protect}: the run budget ended first; not graded")
            raise AssertionError(
                f"instance {instance_id!r} not available with DeletionProtection={protect} after "
                f"{timeout_s}s: status={inst['DBInstanceStatus']!r} "
                f"protection={inst['DeletionProtection']!r}")
        time.sleep(2)


def _instance_snapshots(rds, instance_id: str) -> list[dict]:
    return [s for page in rds.get_paginator("describe_db_snapshots").paginate(
                DBInstanceIdentifier=instance_id, SnapshotType="manual")
            for s in page["DBSnapshots"]]


def _wait_snapshot_available(rds, instance_id: str, timeout_s: int, ctx=None) -> dict:
    deadline = time.monotonic() + timeout_s
    while True:
        snaps = _instance_snapshots(rds, instance_id)
        assert len(snaps) <= 1, (
            f"expected one final snapshot for {instance_id!r}, got "
            f"{[s['DBSnapshotIdentifier'] for s in snaps]!r}")
        if snaps and snaps[0]["Status"] == "available":
            return snaps[0]
        if time.monotonic() > deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(
                    f"final snapshot of {instance_id!r} available: the run budget ended first; not graded")
            raise AssertionError(
                f"no 'available' manual snapshot for deleted instance {instance_id!r} within "
                f"{timeout_s}s: {[(s['DBSnapshotIdentifier'], s['Status']) for s in snaps]!r}")
        time.sleep(2)


def _wait_gone(describe, code: str, what: str, timeout_s: int, ctx=None) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            describe()
        except Exception as exc:  # noqa: BLE001
            got = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if got == code:
                return
            raise
        if time.monotonic() > deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{what} removed: the run budget ended first; not graded")
            raise AssertionError(f"teardown did not remove {what} within {timeout_s}s")
        time.sleep(2)


def _code(exc) -> str:
    return (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")


def _delete_instance_snapshots(rds, instance_id: str) -> None:
    """Delete every manual snapshot of the instance, waiting out 'creating'. A failure raises."""
    deadline = time.monotonic() + 300
    while True:
        try:
            snaps = _instance_snapshots(rds, instance_id)
        except Exception as exc:  # noqa: BLE001
            if _code(exc) != "DBSnapshotNotFound":
                raise
            return
        if not snaps:
            return
        for s in snaps:
            if s["Status"] == "available":
                try:
                    rds.delete_db_snapshot(DBSnapshotIdentifier=s["DBSnapshotIdentifier"])
                except Exception as exc:  # noqa: BLE001
                    if _code(exc) not in ("DBSnapshotNotFound", "InvalidDBSnapshotState"):
                        raise
        if all(s["Status"] == "deleted" for s in snaps):
            return
        if time.monotonic() > deadline:
            raise RuntimeError(f"rds manual snapshot(s) "
                               f"{[(s['DBSnapshotIdentifier'], s['Status']) for s in snaps]!r}")
        time.sleep(2)


def _delete_param_group(rds, pg_name: str) -> None:
    """Delete the retained group. While a live instance still uses it the delete is refused, and
    the stack teardown (runs later) deletes it once the instance is gone."""
    try:
        rds.delete_db_parameter_group(DBParameterGroupName=pg_name)
    except Exception as exc:  # noqa: BLE001
        if _code(exc) not in ("DBParameterGroupNotFound", "InvalidDBParameterGroupState"):
            raise


def _protected(rds, instance_id: str) -> bool:
    try:
        return _describe_instance(rds, instance_id)["DeletionProtection"] is True
    except Exception as exc:  # noqa: BLE001
        if _code(exc) != "DBInstanceNotFound":
            raise
        return False


def _teardown_stack(rds, cfn, stack_id: str) -> None:
    """Lift protection, delete the stack (retrying a DELETE_FAILED once), then remove the
    artifacts the deletion policies leave behind. A failure raises."""
    stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    res = _stack_resources(cfn, stack_id)
    instance_id = res.get(_DB, {}).get("PhysicalResourceId") or None
    pg_name = res.get(_PG, {}).get("PhysicalResourceId") or None
    if stack["StackStatus"] != "DELETE_COMPLETE":
        for attempt in range(2):
            if instance_id and _protected(rds, instance_id):
                rds.modify_db_instance(DBInstanceIdentifier=instance_id,
                                       DeletionProtection=False, ApplyImmediately=True)
                _wait_instance(rds, instance_id, protect=False, timeout_s=300)
            cfn.delete_stack(StackName=stack_id)
            try:
                _wait_stack(cfn, stack_id, "DELETE_COMPLETE", timeout_s=1200)
                break
            except AssertionError:
                if attempt:
                    raise
    if instance_id:
        _delete_instance_snapshots(rds, instance_id)
    if pg_name:
        try:
            rds.delete_db_parameter_group(DBParameterGroupName=pg_name)
        except Exception as exc:  # noqa: BLE001
            if _code(exc) != "DBParameterGroupNotFound":
                raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
