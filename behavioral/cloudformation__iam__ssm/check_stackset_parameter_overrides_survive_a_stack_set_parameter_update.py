"""stackset-parameter-overrides-survive-a-stack-set-parameter-update."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stackset-parameter-overrides-survive-a-stack-set-parameter-update"
GROUP = "stack_sets"
SERVICES = ["cloudformation", "iam", "ssm"]

_OP_TIMEOUT_S = 300.0
_ROLE_RETRY_S = 120.0


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A ParameterOverrides value given to CreateStackInstances lands only in that instance, and a
    later UpdateStackSet parameter change reaches the non-overridden instance while the overridden
    one keeps its override.
    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_UpdateStackSet.html
    """
    cfn = ctx.client("cloudformation")
    region1 = ctx.region
    # us-east-1 and us-west-2 are both default-enabled regions, so one of them always differs from
    # ctx.region; a per-instance override needs two instances, hence two regions.
    region2 = "us-east-1" if region1 != "us-east-1" else "us-west-2"
    account = ctx.account
    admin_name, admin_arn, exec_name = _self_managed_roles(ctx, account)
    role_reasons = {
        f"Account {account} should have '{exec_name}' role with trust relationship to Role '{admin_name}'.",
        f"Account {account} should have '{admin_name}' role with trust relationship to CloudFormation service.",
    }

    param_name = "/" + ctx.unique_name("sim2real-ssovr-")
    base_v1, base_v2, override = (ctx.unique_name(f"{k}-") for k in ("base1", "base2", "override"))
    name = ctx.unique_name("sim2real-ssovr-")
    cfn.create_stack_set(
        StackSetName=name,
        TemplateBody=_TEMPLATE,
        Parameters=[_p("ParamName", param_name), _p("Note", base_v1)],
        PermissionModel="SELF_MANAGED",
        AdministrationRoleARN=admin_arn,
        ExecutionRoleName=exec_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _teardown_stack_set(cfn, name))

    plain = _deploy_instance(cfn, account, name, region1, role_reasons, overrides=[],
                             timeout_s=_cap(ctx, _OP_TIMEOUT_S))
    assert plain == "SUCCEEDED", f"CreateStackInstances in {region1} ended {plain!r}, expected SUCCEEDED"
    overridden = _deploy_instance(cfn, account, name, region2, role_reasons, overrides=[_p("Note", override)],
                                  timeout_s=_cap(ctx, _OP_TIMEOUT_S))
    assert overridden == "SUCCEEDED", (
        f"CreateStackInstances in {region2} with ParameterOverrides ended {overridden!r}, expected "
        f"SUCCEEDED"
    )

    ssm1, ssm2 = ctx.client("ssm", region=region1), ctx.client("ssm", region=region2)
    got = (_value(ssm1, param_name), _value(ssm2, param_name))
    assert got == (base_v1, override), (
        f"parameter {param_name!r} holds {got!r} in ({region1}, {region2}), expected "
        f"{(base_v1, override)!r}: the override must land only in the instance it was given to"
    )
    got = (_overrides(cfn, name, account, region1), _overrides(cfn, name, account, region2))
    assert got == (
        [],
        [(("ParameterKey", "Note"), ("ParameterValue", override), ("UsePreviousValue", False))],
    ), f"DescribeStackInstance ParameterOverrides for ({region1}, {region2}) are {got!r}"

    op_id = cfn.update_stack_set(
        StackSetName=name,
        UsePreviousTemplate=True,
        Parameters=[{"ParameterKey": "ParamName", "UsePreviousValue": True}, _p("Note", base_v2)],
        AdministrationRoleARN=admin_arn,
        ExecutionRoleName=exec_name,
        OperationPreferences={"RegionConcurrencyType": "PARALLEL", "MaxConcurrentCount": 2},
    )["OperationId"]
    updated = _wait_operation(cfn, name, op_id, timeout_s=_cap(ctx, _OP_TIMEOUT_S))
    assert updated == "SUCCEEDED", f"UpdateStackSet operation {op_id} ended {updated!r}, expected SUCCEEDED"

    got = (_value(ssm1, param_name), _value(ssm2, param_name))
    assert got == (base_v2, override), (
        f"after UpdateStackSet(Note={base_v2!r}) parameter {param_name!r} holds {got!r} in "
        f"({region1}, {region2}), expected {(base_v2, override)!r}: the update reaches the "
        f"non-overridden instance and the override survives it"
    )


_TEMPLATE = json.dumps({
    "Parameters": {"ParamName": {"Type": "String"}, "Note": {"Type": "String"}},
    "Resources": {"Param": {"Type": "AWS::SSM::Parameter", "Properties": {
        "Name": {"Ref": "ParamName"}, "Type": "String", "Value": {"Ref": "Note"}}}},
})


def _p(key: str, value: str) -> dict:
    return {"ParameterKey": key, "ParameterValue": value}


def _value(ssm, name: str) -> str:
    return ssm.get_parameter(Name=name)["Parameter"]["Value"]


def _overrides(cfn, name: str, account: str, region: str) -> list:
    instance = cfn.describe_stack_instance(
        StackSetName=name, StackInstanceAccount=account, StackInstanceRegion=region
    )["StackInstance"]
    return [tuple(sorted(o.items())) for o in instance.get("ParameterOverrides", [])]


def _cap(ctx, own_s: float, margin_s: float = 15.0) -> float:
    """Bound a wait by the check's remaining budget."""
    left = ctx.time_left()
    return own_s if left is None else max(1.0, min(own_s, left - margin_s))


def _wait_operation(cfn, name: str, op_id: str, *, timeout_s: float = _OP_TIMEOUT_S) -> str:
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stack_set_operation(
            StackSetName=name, OperationId=op_id)["StackSetOperation"]["Status"]
        if status in ("SUCCEEDED", "FAILED", "STOPPED"):
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack set operation {op_id} still {status} after {timeout_s}s")
        time.sleep(5)


def _role_not_ready(cfn, name: str, op_id: str, role_reasons: set) -> bool:
    """True when every result of the failed operation is one of the exact role-propagation reasons."""
    reasons = {r.get("StatusReason") for page in cfn.get_paginator("list_stack_set_operation_results")
               .paginate(StackSetName=name, OperationId=op_id) for r in page.get("Summaries", [])}
    return bool(reasons) and reasons <= role_reasons


def _deploy_instance(cfn, account: str, name: str, region: str, role_reasons: set, *, overrides: list,
                     timeout_s: float = _OP_TIMEOUT_S) -> str:
    """Create one instance; while new IAM roles propagate, re-drive it with UpdateStackInstances,
    or with CreateStackInstances when the failure left no instance record."""
    deadline = time.monotonic() + _ROLE_RETRY_S
    op_id = cfn.create_stack_instances(
        StackSetName=name, Accounts=[account], Regions=[region], ParameterOverrides=overrides,
    )["OperationId"]
    while True:
        status = _wait_operation(cfn, name, op_id, timeout_s=timeout_s)
        if status != "FAILED" or time.monotonic() > deadline or not _role_not_ready(cfn, name, op_id, role_reasons):
            return status
        time.sleep(5)
        redrive = cfn.update_stack_instances if _has_instance(cfn, name, account, region) else (
            cfn.create_stack_instances)
        op_id = redrive(
            StackSetName=name, Accounts=[account], Regions=[region], ParameterOverrides=overrides,
        )["OperationId"]


def _has_instance(cfn, name: str, account: str, region: str) -> bool:
    """Whether the stack set holds an instance record for the account and region."""
    try:
        cfn.describe_stack_instance(StackSetName=name, StackInstanceAccount=account,
                                    StackInstanceRegion=region)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "StackInstanceNotFoundException":
            return False
        raise
    return True


def _self_managed_roles(ctx, account: str) -> tuple[str, str, str]:
    """A check-owned administration/execution role pair with inline policies only."""
    iam = ctx.client("iam")
    admin_name = ctx.unique_name("sim2real-ssovr-adm-")
    exec_name = ctx.unique_name("sim2real-ssovr-exe-")
    tag = [{"Key": "sim2real-check", "Value": CHECK}]
    admin_trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Principal": {"Service": "cloudformation.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    admin_arn = iam.create_role(RoleName=admin_name, AssumeRolePolicyDocument=json.dumps(admin_trust),
                                Tags=tag)["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, admin_name))
    exec_trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Principal": {"AWS": admin_arn}, "Action": "sts:AssumeRole"}]}
    deadline = time.monotonic() + _ROLE_RETRY_S
    while True:
        try:
            iam.create_role(RoleName=exec_name, AssumeRolePolicyDocument=json.dumps(exec_trust), Tags=tag)
            break
        except ClientError as exc:
            # A just-created role ARN is briefly not yet a valid Principal.
            if exc.response["Error"]["Code"] != "MalformedPolicyDocument" or time.monotonic() > deadline:
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: _delete_role(iam, exec_name))
    iam.put_role_policy(RoleName=exec_name, PolicyName="StackSetWork", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Resource": "*", "Action": [
            "cloudformation:*", "ssm:PutParameter", "ssm:DeleteParameter", "ssm:GetParameter",
            "ssm:GetParameters", "ssm:AddTagsToResource", "ssm:RemoveTagsFromResource",
            "ssm:ListTagsForResource"]}]}))
    iam.put_role_policy(RoleName=admin_name, PolicyName="AssumeExecRole", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
            "Resource": f"arn:aws:iam::{account}:role/{exec_name}"}]}))
    return admin_name, admin_arn, exec_name


def _delete_role(iam, role_name: str) -> None:
    """Delete the role's inline policies, then the role; only NoSuchEntity is tolerated."""
    try:
        for policy in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy)
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _teardown_stack_set(cfn, name: str) -> None:
    """Wait out open operations, delete every instance (and its stack), wait for that operation,
    then delete the set."""
    try:
        ops = [op for page in cfn.get_paginator("list_stack_set_operations").paginate(StackSetName=name)
               for op in page.get("Summaries", [])]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "StackSetNotFoundException":
            return
        raise
    for op in ops:
        if op["Status"] in ("RUNNING", "QUEUED", "STOPPING"):
            _wait_operation(cfn, name, op["OperationId"])
    try:
        summaries = [s for page in cfn.get_paginator("list_stack_instances").paginate(StackSetName=name)
                     for s in page.get("Summaries", [])]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "StackSetNotFoundException":
            return
        raise
    if summaries:
        regions = sorted({s["Region"] for s in summaries})
        op_id = cfn.delete_stack_instances(
            StackSetName=name, Accounts=sorted({s["Account"] for s in summaries}), Regions=regions,
            RetainStacks=False,
            OperationPreferences={"RegionConcurrencyType": "PARALLEL", "MaxConcurrentCount": len(regions)},
        )["OperationId"]
        status = _wait_operation(cfn, name, op_id)
        if status != "SUCCEEDED":
            raise AssertionError(f"DeleteStackInstances on {name} ended {status}")
    cfn.delete_stack_set(StackSetName=name)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
