"""deploy-cfn-stack-update-modifies-live-parameter-group."""
from __future__ import annotations

import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-stack-update-modifies-live-parameter-group"
GROUP = "deploy"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "cap:c5", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Updating the CFN template's DBParameterGroupName property causes the live
    instance's associated parameter group and effective parameter values to
    change in place, without resource replacement."""
    rds = ctx.client("rds")
    versions = rds.describe_db_engine_versions(Engine="mysql", DefaultOnly=True)["DBEngineVersions"]
    if not versions:
        raise AssertionError("no default mysql engine version available to derive a parameter group family")
    engine_version = versions[0]["EngineVersion"]
    family = versions[0]["DBParameterGroupFamily"]

    candidate = _find_dynamic_boolean_parameter(rds, family)
    if candidate is None:
        raise AssertionError(
            f"no dynamic, modifiable boolean parameter found in family {family!r}; "
            "cannot exercise a live (no-reboot) parameter-group value change"
        )
    param_name = candidate["ParameterName"]
    allowed = [v.strip() for v in candidate.get("AllowedValues", "0,1").split(",") if v.strip()]
    default_val = candidate.get("ParameterValue")
    new_value = next((v for v in allowed if v != default_val), allowed[0] if allowed else "0")

    group_a = ctx.unique_name("sim2real-rds-pga-")
    group_b = ctx.unique_name("sim2real-rds-pgb-")
    instance_id = ctx.unique_name("sim2real-rds-pginst-")
    password = _gen_password()
    # One subnet group for both template versions: a changed DBSubnetGroupName would make the
    # update replace the named instance, which CloudFormation cannot do (update rollback).
    subnet_group = _network_db_subnet_group(ctx, rds)

    template_v1 = f"""AWSTemplateFormatVersion: '2010-09-09'
Resources:
  ParamGroupA:
    Type: AWS::RDS::DBParameterGroup
    Properties:
      DBParameterGroupName: {group_a}
      Description: sim2real group A
      Family: {family}
      Tags:
        - Key: sim2real:managed
          Value: "true"
  DBInstance:
    Type: AWS::RDS::DBInstance
    DeletionPolicy: Delete
    Properties:
      DBSubnetGroupName: {subnet_group}
      DBInstanceIdentifier: {instance_id}
      Engine: mysql
      EngineVersion: {engine_version}
      DBInstanceClass: db.t3.micro
      AllocatedStorage: 20
      MasterUsername: sim2realadmin
      MasterUserPassword: {password}
      DBParameterGroupName: !Ref ParamGroupA
      BackupRetentionPeriod: 0
      PubliclyAccessible: false
      Tags:
        - Key: sim2real:managed
          Value: "true"
"""
    stack_name = _deploy_cfn_stack(ctx, template_v1)

    instance = _describe_db_instance(rds, instance_id)
    baseline_resource_id = instance["DbiResourceId"]
    assert instance["DBParameterGroups"][0]["DBParameterGroupName"].lower() == group_a.lower(), instance

    template_v2 = f"""AWSTemplateFormatVersion: '2010-09-09'
Resources:
  ParamGroupA:
    Type: AWS::RDS::DBParameterGroup
    Properties:
      DBParameterGroupName: {group_a}
      Description: sim2real group A
      Family: {family}
      Tags:
        - Key: sim2real:managed
          Value: "true"
  ParamGroupB:
    Type: AWS::RDS::DBParameterGroup
    Properties:
      DBParameterGroupName: {group_b}
      Description: sim2real group B
      Family: {family}
      Parameters:
        {param_name}: "{new_value}"
      Tags:
        - Key: sim2real:managed
          Value: "true"
  DBInstance:
    Type: AWS::RDS::DBInstance
    DeletionPolicy: Delete
    Properties:
      DBSubnetGroupName: {subnet_group}
      DBInstanceIdentifier: {instance_id}
      Engine: mysql
      EngineVersion: {engine_version}
      DBInstanceClass: db.t3.micro
      AllocatedStorage: 20
      MasterUsername: sim2realadmin
      MasterUserPassword: {password}
      DBParameterGroupName: !Ref ParamGroupB
      BackupRetentionPeriod: 0
      PubliclyAccessible: false
      Tags:
        - Key: sim2real:managed
          Value: "true"
"""
    cfn = ctx.client("cloudformation")
    cfn.update_stack(
        StackName=stack_name,
        TemplateBody=template_v2,
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    _wait_stack_status(ctx, stack_name, {"UPDATE_COMPLETE"}, 1800)

    instance_after = _poll_until_param_group(rds, instance_id, group_b, timeout_s=_budget_s(ctx, 300), ctx=ctx)
    assert instance_after["DbiResourceId"] == baseline_resource_id, (
        "instance was replaced (DbiResourceId changed) instead of modified in place"
    )
    assert instance_after["DBParameterGroups"][0]["ParameterApplyStatus"] == "in-sync", instance_after

    params = rds.describe_db_parameters(DBParameterGroupName=group_b)["Parameters"]
    match = next((p for p in params if p["ParameterName"] == param_name), None)
    assert match is not None, f"{param_name} not present in {group_b} parameters"
    assert match["ParameterValue"] == new_value, match
    assert match["Source"] == "user", match


# ===== helpers =====

def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _gen_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _find_dynamic_boolean_parameter(rds, family):
    marker = None
    for _ in range(10):
        kwargs = {"DBParameterGroupFamily": family, "MaxRecords": 100}
        if marker:
            kwargs["Marker"] = marker
        resp = rds.describe_engine_default_parameters(**kwargs)
        defaults = resp["EngineDefaults"]
        for p in defaults.get("Parameters", []):
            if (
                p.get("ApplyType") == "dynamic"
                and p.get("IsModifiable")
                and p.get("DataType") == "boolean"
            ):
                return p
        marker = defaults.get("Marker")
        if not marker:
            break
    return None


def _deploy_cfn_stack(ctx, template_body: str, timeout_s: int = 1800) -> str:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-rds-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    _wait_stack_status(ctx, stack_name, {"CREATE_COMPLETE"}, timeout_s)
    return stack_name


def _delete_stack(ctx, stack_name: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; a stack already gone counts as deleted,
    DELETE_FAILED or any other describe error raises."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 850}
    )


def _wait_stack_status(ctx, stack_name, ok_statuses, timeout_s, allow_not_found=False):
    cfn = ctx.client("cloudformation")
    bad_statuses = {
        "CREATE_FAILED", "ROLLBACK_IN_PROGRESS", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
        "UPDATE_ROLLBACK_IN_PROGRESS", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
        "DELETE_FAILED", "UPDATE_FAILED",
    } - set(ok_statuses)
    if not allow_not_found:
        timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = cfn.describe_stacks(StackName=stack_name)
        except Exception:
            if allow_not_found:
                return "DELETE_COMPLETE"
            raise
        status = resp["Stacks"][0]["StackStatus"]
        if status in ok_statuses:
            return status
        if status in bad_statuses:
            raise AssertionError(f"stack {stack_name} reached unexpected status {status}")
        time.sleep(2)
    if not allow_not_found and _budget_spent(ctx):
        raise TimeoutError(f"stack {stack_name} {ok_statuses}: the run budget ended first; not graded")
    raise AssertionError(f"stack {stack_name} did not reach {ok_statuses} within {timeout_s}s")


def _describe_db_instance(rds, instance_id):
    return rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]


def _poll_until_param_group(rds, instance_id, expected_group_name, timeout_s=300.0, interval_s=2.0, *, ctx):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _describe_db_instance(rds, instance_id)
        groups = last.get("DBParameterGroups", [])
        if (groups and groups[0]["DBParameterGroupName"].lower() == expected_group_name.lower()
                and groups[0].get("ParameterApplyStatus") == "in-sync"):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(
            f"instance {instance_id} parameter group {expected_group_name} in-sync: "
            "the run budget ended first; not graded"
        )
    raise AssertionError(
        f"instance {instance_id} never associated in-sync with parameter group {expected_group_name}; "
        f"last seen: {last}"
    )


def _network_db_subnet_group(ctx, client) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_db_subnet_group(DBSubnetGroupName=name),
            ("InvalidDBSubnetGroupStateFault", "InvalidDBSubnetGroupState"),
            ("DBSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=100.0, interval_s=2.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
