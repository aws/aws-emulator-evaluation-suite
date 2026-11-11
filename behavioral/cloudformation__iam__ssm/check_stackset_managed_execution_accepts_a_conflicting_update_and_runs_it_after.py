"""stackset-managed-execution-accepts-a-conflicting-update-and-runs-it-after."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stackset-managed-execution-accepts-a-conflicting-update-and-runs-it-after"
GROUP = "stack_sets"
SERVICES = ["cloudformation", "iam", "ssm"]

_OP_TIMEOUT_S = 300.0
_ROLE_RETRY_S = 120.0
_TERMINAL = ("SUCCEEDED", "FAILED", "STOPPED")


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """While CreateStackInstances is held by an unsignalled WaitCondition, a ManagedExecution stack set
    accepts a conflicting UpdateStackSet as QUEUED and runs it after the held operation, while the same
    update on a stack set without ManagedExecution is refused with the exact OperationInProgressException.
    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_ManagedExecution.html
    """
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    account = ctx.account
    admin_name, admin_arn, exec_name = _self_managed_roles(ctx, account)
    role_reasons = {
        f"Account {account} should have '{exec_name}' role with trust relationship to Role '{admin_name}'.",
        f"Account {account} should have '{admin_name}' role with trust relationship to CloudFormation service.",
    }
    v1, v2 = ctx.unique_name("v1-"), ctx.unique_name("v2-")

    sets = {}
    for label, managed in (("managed", {"Active": True}), ("plain", {"Active": False})):
        name = ctx.unique_name(f"sim2real-ssmx-{label}-")
        param = "/" + ctx.unique_name(f"sim2real-ssmx-{label}-")
        cfn.create_stack_set(
            StackSetName=name, TemplateBody=_TEMPLATE,
            Parameters=[_p("ParamName", param), _p("Note", v1)],
            PermissionModel="SELF_MANAGED", AdministrationRoleARN=admin_arn, ExecutionRoleName=exec_name,
            ManagedExecution=managed, Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )
        ctx.on_cleanup(lambda name=name: _teardown_stack_set(cfn, name))
        got = cfn.describe_stack_set(StackSetName=name)["StackSet"].get("ManagedExecution")
        assert got == managed, f"DescribeStackSet ManagedExecution of {label} is {got!r}, expected {managed!r}"
        op1, stack_id = _start_held_instance(cfn, account, name, ctx.region, role_reasons,
                                             timeout_s=_cap(ctx, _OP_TIMEOUT_S))
        sets[label] = {"name": name, "param": param, "op1": op1, "stack_id": stack_id}

    def update(name: str):
        return lambda: cfn.update_stack_set(
            StackSetName=name, UsePreviousTemplate=True,
            Parameters=[{"ParameterKey": "ParamName", "UsePreviousValue": True}, _p("Note", v2)],
            AdministrationRoleARN=admin_arn, ExecutionRoleName=exec_name,
        )["OperationId"]

    managed, plain = sets["managed"], sets["plain"]
    op2 = update(managed["name"])()
    got = (_op(cfn, managed["name"], managed["op1"])["Status"], _op(cfn, managed["name"], op2)["Status"],
           _gate_status(cfn, managed["stack_id"]))
    assert got == ("RUNNING", "QUEUED", "CREATE_IN_PROGRESS"), (
        f"(held operation, conflicting update, Gate) on the ManagedExecution set are {got!r}, "
        f"expected ('RUNNING', 'QUEUED', 'CREATE_IN_PROGRESS')")

    refused = _error(update(plain["name"]))
    arn = cfn.describe_stack_set(StackSetName=plain["name"])["StackSet"]["StackSetARN"]
    want = ("OperationInProgressException", f"Another Operation on StackSet {arn} is in progress: {plain['op1']}")
    assert refused == want, f"UpdateStackSet on the set without ManagedExecution: expected {want!r}, got {refused!r}"

    for s in (managed, plain):
        cfn.signal_resource(StackName=s["stack_id"], LogicalResourceId="Gate",
                            UniqueId=ctx.unique_name("sig-"), Status="SUCCESS")
    statuses = tuple(_wait_operation(cfn, s["name"], op, timeout_s=_cap(ctx, _OP_TIMEOUT_S))
                     for s, op in ((managed, managed["op1"]), (managed, op2), (plain, plain["op1"])))
    assert statuses == ("SUCCEEDED", "SUCCEEDED", "SUCCEEDED"), (
        f"(managed create, queued update, plain create) ended {statuses!r}, expected all SUCCEEDED")
    first, second = _op(cfn, managed["name"], managed["op1"]), _op(cfn, managed["name"], op2)
    assert second["EndTimestamp"] >= first["EndTimestamp"], (
        f"the queued update finished at {second['EndTimestamp']!r}, before the held operation it "
        f"waited for ({first['EndTimestamp']!r})")
    values = (_value(ssm, managed["param"]), _value(ssm, plain["param"]))
    assert values == (v2, v1), (
        f"parameters (managed, plain) hold {values!r}, expected {(v2, v1)!r}: the queued update ran "
        f"and the refused one changed nothing")


_TEMPLATE = json.dumps({
    "Parameters": {"ParamName": {"Type": "String"}, "Note": {"Type": "String"}},
    "Resources": {
        "Param": {"Type": "AWS::SSM::Parameter", "Properties": {
            "Name": {"Ref": "ParamName"}, "Type": "String", "Value": {"Ref": "Note"}}},
        # Held until the check calls SignalResource, so the create cannot finish on its own.
        "Gate": {"Type": "AWS::CloudFormation::WaitCondition",
                 "CreationPolicy": {"ResourceSignal": {"Count": 1, "Timeout": "PT15M"}}},
    },
})


def _p(key: str, value: str) -> dict:
    return {"ParameterKey": key, "ParameterValue": value}


def _cap(ctx, own_s: float, margin_s: float = 15.0) -> float:
    """Bound a wait by the check's remaining budget."""
    left = ctx.time_left()
    return own_s if left is None else max(1.0, min(own_s, left - margin_s))


def _error(fn) -> tuple:
    """(code, message) of the ClientError fn() raises; a success fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, it succeeded with {result!r}")


def _value(ssm, name: str) -> str:
    return ssm.get_parameter(Name=name)["Parameter"]["Value"]


def _op(cfn, name: str, op_id: str) -> dict:
    return cfn.describe_stack_set_operation(StackSetName=name, OperationId=op_id)["StackSetOperation"]


def _wait_operation(cfn, name: str, op_id: str, *, timeout_s: float = _OP_TIMEOUT_S) -> str:
    deadline = time.monotonic() + timeout_s
    while True:
        status = _op(cfn, name, op_id)["Status"]
        if status in _TERMINAL:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack set operation {op_id} still {status} after {timeout_s}s")
        time.sleep(5)


def _gate_status(cfn, stack_id: str):
    """The Gate's ResourceStatus, or None while the instance stack has not created it yet."""
    try:
        return cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId="Gate")[
            "StackResourceDetail"]["ResourceStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ValidationError":
            raise
        return None


def _start_held_instance(cfn, account: str, name: str, region: str, role_reasons: set, *,
                         timeout_s: float) -> tuple[str, str]:
    """Create a stack instance, redriving past role propagation, until it holds at its Gate.

    A propagation failure can end the operation FAILED either before or after it first reports
    RUNNING, with one of the exact ``role_reasons``; either is redriven with UpdateStackInstances.
    Returns (operation id, StackId) once the instance stack holds CREATE_IN_PROGRESS at its Gate.
    """
    deadline = time.monotonic() + timeout_s
    op_id = cfn.create_stack_instances(StackSetName=name, Accounts=[account], Regions=[region])["OperationId"]
    while True:
        op = _op(cfn, name, op_id)["Status"]
        stack_id = _instance_stack_id(cfn, account, name, region)
        gate = _gate_status(cfn, stack_id) if stack_id else None
        if op == "RUNNING" and gate == "CREATE_IN_PROGRESS":
            return op_id, stack_id
        if op in _TERMINAL:
            reasons = {r.get("StatusReason") for page in cfn.get_paginator("list_stack_set_operation_results")
                       .paginate(StackSetName=name, OperationId=op_id) for r in page.get("Summaries", [])}
            if op != "FAILED" or not reasons or not reasons <= role_reasons or time.monotonic() > deadline:
                raise AssertionError(
                    f"operation {op_id} on {name} ended {op} before holding its Gate: reasons {reasons!r}")
            time.sleep(5)
            # A failure before the instance record ever appeared needs CreateStackInstances again;
            # UpdateStackInstances on a nonexistent instance raises StackInstanceNotFoundException.
            redrive = cfn.create_stack_instances if stack_id is None else cfn.update_stack_instances
            op_id = redrive(StackSetName=name, Accounts=[account], Regions=[region])["OperationId"]
            continue
        if time.monotonic() > deadline:
            raise AssertionError(
                f"operation {op_id} on {name} never held at its Gate within {timeout_s}s: op {op}, Gate {gate}")
        time.sleep(3)


def _instance_stack_id(cfn, account: str, name: str, region: str) -> str | None:
    """The instance's StackId, or None while the account/region has no instance yet."""
    try:
        return cfn.describe_stack_instance(StackSetName=name, StackInstanceAccount=account,
                                           StackInstanceRegion=region)["StackInstance"].get("StackId")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackInstanceNotFoundException":
            raise
        return None


def _self_managed_roles(ctx, account: str) -> tuple[str, str, str]:
    """A check-owned administration/execution role pair with inline policies only."""
    iam = ctx.client("iam")
    admin_name = ctx.unique_name("sim2real-ssmx-adm-")
    exec_name = ctx.unique_name("sim2real-ssmx-exe-")
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
    """Fail a still-held Gate, wait out open operations, delete every instance, then the set."""
    try:
        summaries = [s for page in cfn.get_paginator("list_stack_instances").paginate(StackSetName=name)
                     for s in page.get("Summaries", [])]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "StackSetNotFoundException":
            return
        raise
    for s in summaries:
        if s.get("StackId") and _gate_status(cfn, s["StackId"]) == "CREATE_IN_PROGRESS":
            cfn.signal_resource(StackName=s["StackId"], LogicalResourceId="Gate",
                                UniqueId="sim2real-cleanup", Status="FAILURE")
    for page in cfn.get_paginator("list_stack_set_operations").paginate(StackSetName=name):
        for o in page.get("Summaries", []):
            if o["Status"] not in _TERMINAL:
                _wait_operation(cfn, name, o["OperationId"], timeout_s=600.0)
    if summaries:
        regions = sorted({s["Region"] for s in summaries})
        op_id = cfn.delete_stack_instances(
            StackSetName=name, Accounts=sorted({s["Account"] for s in summaries}), Regions=regions,
            RetainStacks=False,
            OperationPreferences={"RegionConcurrencyType": "PARALLEL", "MaxConcurrentCount": len(regions)},
        )["OperationId"]
        status = _wait_operation(cfn, name, op_id, timeout_s=600.0)
        if status != "SUCCEEDED":
            raise AssertionError(f"DeleteStackInstances on {name} ended {status}")
    cfn.delete_stack_set(StackSetName=name)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
