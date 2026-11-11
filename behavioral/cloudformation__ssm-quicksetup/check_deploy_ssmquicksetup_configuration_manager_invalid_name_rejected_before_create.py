"""deploy-ssmquicksetup-configuration-manager-invalid-name-rejected-before-create."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-ssmquicksetup-configuration-manager-invalid-name-rejected-before-create"
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


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


# ---- Check-specific: the template, then run(). ----


_NAME_PATTERN = "^[ A-Za-z0-9_-]{1,50}$"
_TYPE = "AWSQuickSetupType-Distributor"


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
                    "ConfigurationDefinitions": [{
                        "Type": _TYPE,
                        "Parameters": {
                            "PackagesToInstall": "AWSEC2LaunchAgent",
                            "TargetType": "Tags",
                            "TargetTagKey": tag_key,
                            "TargetTagValue": tag_value,
                            "TargetAccounts": {"Ref": "AWS::AccountId"},
                            "TargetRegions": {"Ref": "AWS::Region"},
                        },
                        "LocalDeploymentAdministrationRoleArn": {"Fn::GetAtt": ["AdminRole", "Arn"]},
                        "LocalDeploymentExecutionRoleName": {"Ref": "ExecRole"},
                    }],
                },
            },
        },
        "Outputs": {
            "ManagerArnRef": {"Value": {"Ref": "ConfigManager"}},
        },
    })


def _require_no_manager_of_type(qs, definition_type):
    """Precondition: no configuration manager of ``definition_type`` exists in the account."""
    managers = paginate(qs, "list_configuration_managers", "ConfigurationManagersList")
    same = [m["ManagerArn"] for m in managers
            if any(d.get("Type") == definition_type
                   for d in m.get("ConfigurationDefinitionSummaries", []))]
    assert same == [], (
        f"precondition: the account already has {definition_type} configuration managers {same!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control",
      "resource:account-singleton:ssm-quicksetup-configuration-manager")
def run(ctx) -> None:
    """A CloudFormation Quick Setup configuration manager whose Name breaks its pattern fails validation.

    No manager of that name is listed, while the same template with a valid Name deploys and reads
    back through ssm-quicksetup.
    """
    cfn = ctx.client("cloudformation")
    qs = ctx.client("ssm-quicksetup")
    _require_no_manager_of_type(qs, _TYPE)
    tag_key = ctx.unique_name("sim2real-qscfnneg-key-")
    tag_value = ctx.unique_name("sim2real-qscfnneg-val-")
    admin_role = ctx.unique_name("sim2real-qscfnneg-admin-")
    exec_role = ctx.unique_name("sim2real-qscfnneg-exec-")

    # Negative: the Name breaks the registry pattern, refused before anything is provisioned.
    good_name = ctx.unique_name("sim2real-qscfnneg-")[:50]
    bad_name = "bad!" + good_name
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-qscfnneg-"),
                          _template(bad_name, tag_key, tag_value, admin_role, exec_role),
                          Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = validation_rows(cfn, bad_id)
    want_rows = [(
        "ConfigManager", "PROPERTY_VALIDATION", "FAILED", "FAIL",
        f"Property value [{bad_name}] does not match pattern: {_NAME_PATTERN}",
        "/Resources/ConfigManager/Properties/Name",
    )]
    assert rows == want_rows, f"validation rows {rows!r}, expected {want_rows!r}"
    listed = [m["ManagerArn"] for m in paginate(qs, "list_configuration_managers",
                                                "ConfigurationManagersList")
              if m.get("Name") in (bad_name, good_name)]
    assert listed == [], f"a manager of the rejected template is listed: {listed!r}"
    delete_stack(cfn, bad_id)

    # Positive control: the same template with the one property given a VALID value.
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-qscfnneg-"),
                           _template(good_name, tag_key, tag_value, admin_role, exec_role),
                           Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cfn, good_id, timeout_s=900.0)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    manager_arn = stack_outputs(cfn, good_id)["ManagerArnRef"]
    listed = [m["ManagerArn"] for m in paginate(qs, "list_configuration_managers",
                                                "ConfigurationManagersList")
              if m.get("Name") == good_name]
    assert listed == [manager_arn], f"ListConfigurationManagers found {listed!r}"
    got = qs.get_configuration_manager(ManagerArn=manager_arn)
    got_def = [(d["Type"], d["Parameters"]["TargetTagKey"]) for d in got["ConfigurationDefinitions"]]
    assert (got["Name"], got_def) == (good_name, [(_TYPE, tag_key)]), (
        f"control manager reads {got['Name']!r}, {got_def!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
