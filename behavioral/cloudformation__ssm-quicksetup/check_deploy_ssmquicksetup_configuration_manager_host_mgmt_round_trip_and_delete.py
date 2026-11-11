"""deploy-ssmquicksetup-configuration-manager-host-mgmt-round-trip-and-delete."""
from __future__ import annotations

import json
import time
from datetime import datetime

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ssmquicksetup-configuration-manager-host-mgmt-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ssm-quicksetup"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

_TYPE = "AWSQuickSetupType-SSMHostMgmt"
_PARAMETERS = {"CollectInventory": "false", "ScanInstances": "false", "UpdateSsmAgent": "false",
               "UpdateEc2LaunchAgent": "false", "InstallCloudWatchAgent": "false",
               "UpdateCloudWatchAgent": "false"}


def _template(
    manager_name: str, tag_key: str, tag_value: str, admin_role_name: str, exec_role_name: str,
) -> str:
    admin_role_arn = {"Fn::Sub": f"arn:${{AWS::Partition}}:iam::${{AWS::AccountId}}:role/{admin_role_name}"}
    exec_role_arn = {"Fn::Sub": f"arn:${{AWS::Partition}}:iam::${{AWS::AccountId}}:role/{exec_role_name}"}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "AdminRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": admin_role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": ["cloudformation.amazonaws.com",
                                                      "ssm-quicksetup.amazonaws.com"]},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                    "Policies": [{
                        "PolicyName": "AssumeLocalExecutionRole",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": "sts:AssumeRole",
                                "Resource": exec_role_arn,
                            }],
                        },
                    }],
                },
            },
            "ExecRole": {
                "Type": "AWS::IAM::Role",
                "DependsOn": "AdminRole",
                "Properties": {
                    "RoleName": exec_role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"AWS": admin_role_arn},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                    "ManagedPolicyArns": [
                        {"Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/AWSCloudFormationFullAccess"},
                        {"Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/AmazonSSMFullAccess"},
                        {"Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/IAMFullAccess"},
                    ],
                },
            },
            "ConfigManager": {
                "Type": "AWS::SSMQuickSetup::ConfigurationManager",
                "Properties": {
                    "Name": manager_name,
                    "Description": "sim2real CFN host management round trip",
                    "ConfigurationDefinitions": [{
                        "Type": _TYPE,
                        "Parameters": {
                            "TargetType": "Tags",
                            "TargetTagKey": tag_key,
                            "TargetTagValue": tag_value,
                            "TargetAccounts": {"Ref": "AWS::AccountId"},
                            "TargetRegions": {"Ref": "AWS::Region"},
                            **_PARAMETERS,
                        },
                        "LocalDeploymentAdministrationRoleArn": {"Fn::GetAtt": ["AdminRole", "Arn"]},
                        "LocalDeploymentExecutionRoleName": {"Ref": "ExecRole"},
                    }],
                    "Tags": {"sim2real-resource": manager_name},
                },
            },
        },
        "Outputs": {
            "ManagerArnRef": {"Value": {"Ref": "ConfigManager"}},
            "ManagerCreatedAt": {"Value": {"Fn::GetAtt": ["ConfigManager", "CreatedAt"]}},
        },
    })


# The manager's deployment runs inside the suite budget beside the stack create and delete.
_DEPLOYMENT_TIMEOUT_S = 600.0
_STACK_SETS_GONE_TIMEOUT_S = 300.0


def _wait_manager_deployment_terminal(qs, manager_arn: str,
                                      timeout_s: float = _DEPLOYMENT_TIMEOUT_S) -> str:
    """Polls GetConfigurationManager's Deployment StatusSummary to a terminal state."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        summaries = qs.get_configuration_manager(ManagerArn=manager_arn).get("StatusSummaries", [])
        entry = next((s for s in summaries if s["StatusType"] == "Deployment"), None)
        status = entry["Status"] if entry else None
        if status in ("SUCCEEDED", "FAILED", "STOPPED", "DELETE_FAILED", "STOP_FAILED"):
            return status
        time.sleep(5)
    raise AssertionError(f"manager {manager_arn} deployment not terminal within {timeout_s}s")


def _active_stack_sets_of(cfn, admin_role_arn: str) -> list[str]:
    """Names of the ACTIVE stack sets administered by ``admin_role_arn``: Quick Setup's own."""
    names = [s["StackSetName"] for s in paginate(cfn, "list_stack_sets", "Summaries",
                                                  Status="ACTIVE")]
    return sorted(n for n in names if cfn.describe_stack_set(StackSetName=n)["StackSet"].get(
        "AdministrationRoleARN") == admin_role_arn)


def _wait_stack_sets_gone(cfn, admin_role_arn: str, timeout_s: float) -> None:
    """Poll until no ACTIVE stack set is administered by ``admin_role_arn``; raise naming them."""
    deadline = time.monotonic() + timeout_s
    while True:
        left = _active_stack_sets_of(cfn, admin_role_arn)
        if not left:
            return
        if time.monotonic() > deadline:
            raise AssertionError(
                f"Quick Setup stack sets {left!r} still ACTIVE {timeout_s:.0f} s after the delete"
            )
        time.sleep(2)


def _require_no_manager_of_type(qs, definition_type):
    """Precondition: no configuration manager of ``definition_type`` exists in the account."""
    managers = paginate(qs, "list_configuration_managers", "ConfigurationManagersList")
    same = [m["ManagerArn"] for m in managers
            if any(d.get("Type") == definition_type
                   for d in m.get("ConfigurationDefinitionSummaries", []))]
    assert same == [], (
        f"precondition: the account already has {definition_type} configuration managers {same!r}"
    )


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control", "resource:account-singleton:ssm-quicksetup-configuration-manager")
def run(ctx) -> None:
    """A CloudFormation Quick Setup host-management configuration manager reads back exactly.

    Ref, CreatedAt, every templated property and the tags match ssm-quicksetup, its deployment
    succeeds through stack sets, and deleting the stack removes the manager and those stack sets.
    """
    cfn = ctx.client("cloudformation")
    qs = ctx.client("ssm-quicksetup")
    _require_no_manager_of_type(qs, _TYPE)

    stack = ctx.unique_name("sim2real-qscfn-")
    manager_name = ctx.unique_name("sim2real-qscfn-")[:50]
    tag_key = ctx.unique_name("sim2real-qscfn-key-")
    tag_value = ctx.unique_name("sim2real-qscfn-val-")
    admin_role_name = ctx.unique_name("sim2real-qscfn-admin-")
    exec_role_name = ctx.unique_name("sim2real-qscfn-exec-")

    stack_id = create_stack(
        ctx, cfn, stack,
        _template(manager_name, tag_key, tag_value, admin_role_name, exec_role_name),
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )
    status = wait_stack(cfn, stack_id, timeout_s=900.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]
    manager_arn = outputs["ManagerArnRef"]

    # Ref == the ARN an independent ListConfigurationManagers reports for the templated name.
    listed = [m for m in paginate(qs, "list_configuration_managers", "ConfigurationManagersList")
              if m.get("Name") == manager_name]
    assert [m["ManagerArn"] for m in listed] == [manager_arn], (
        f"ListConfigurationManagers found {listed!r} for Ref {manager_arn!r}"
    )

    got = qs.get_configuration_manager(ManagerArn=manager_arn)
    created_at = datetime.fromisoformat(outputs["ManagerCreatedAt"].replace("Z", "+00:00"))
    assert (got["ManagerArn"], got["Name"], got["Description"], got["CreatedAt"]) == (
        manager_arn, manager_name, "sim2real CFN host management round trip", created_at
    ), f"GetConfigurationManager reads {got!r}"
    definitions = [(d["Type"], d["Parameters"], d["LocalDeploymentAdministrationRoleArn"],
                    d["LocalDeploymentExecutionRoleName"])
                   for d in got["ConfigurationDefinitions"]]
    want_parameters = {"TargetType": "Tags", "TargetTagKey": tag_key, "TargetTagValue": tag_value,
                       "TargetAccounts": ctx.account, "TargetRegions": ctx.region, **_PARAMETERS}
    admin_arn = f"arn:{partition}:iam::{ctx.account}:role/{admin_role_name}"
    assert definitions == [(_TYPE, want_parameters, admin_arn, exec_role_name)], (
        f"configuration definitions {definitions!r}"
    )
    own_tags = {r["Key"]: r["Value"] for r in qs.list_tags_for_resource(
        ResourceArn=manager_arn)["Tags"] if not r["Key"].startswith("aws:")}
    assert own_tags == {"sim2real": stack, "sim2real-resource": manager_name}, (
        f"manager tags {own_tags!r}"
    )

    deployment_status = _wait_manager_deployment_terminal(qs, manager_arn)
    assert deployment_status == "SUCCEEDED", f"host management deployment {deployment_status!r}"
    # The deployment runs through stack sets administered by the templated admin role.
    deployed_sets = _active_stack_sets_of(cfn, admin_arn)
    assert deployed_sets, f"no ACTIVE stack set is administered by {admin_role_name!r}"

    delete_stack(cfn, stack_id)
    gone = ("ResourceNotFoundException",
            f"Quick setup manager with arn: {manager_arn} could not be found.")
    expect_error(lambda: qs.get_configuration_manager(ManagerArn=manager_arn), *gone)
    # Quick Setup's own stack sets for this manager go with it, so nothing it deployed leaks.
    _wait_stack_sets_gone(cfn, admin_arn, _STACK_SETS_GONE_TIMEOUT_S)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
