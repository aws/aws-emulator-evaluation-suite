"""deploy-cfn-codedeploy-deploymentgroup-invalid-role-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-codedeploy-deploymentgroup-invalid-role-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "codedeploy", "iam"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


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


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


def handler_reason(reason, account, *names):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


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

def _template() -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {"ServiceRoleArn": {"Type": "String"}, "TagFilterKey": {"Type": "String"}},
            "Resources": {
                "CDApplication": {
                    "Type": "AWS::CodeDeploy::Application",
                    "Properties": {"ComputePlatform": "Server"},
                },
                "CDDeploymentGroup": {
                    "Type": "AWS::CodeDeploy::DeploymentGroup",
                    "Properties": {
                        "ApplicationName": {"Ref": "CDApplication"},
                        "ServiceRoleArn": {"Ref": "ServiceRoleArn"},
                        "Ec2TagFilters": [
                            {"Key": {"Ref": "TagFilterKey"}, "Value": "none", "Type": "KEY_AND_VALUE"}
                        ],
                    },
                },
            },
            "Outputs": {
                "ApplicationName": {"Value": {"Ref": "CDApplication"}},
                "DeploymentGroupName": {"Value": {"Ref": "CDDeploymentGroup"}},
            },
        }
    )


def _teardown(undo, *not_found: str):
    """A setup cleanup where only the ``not_found`` codes mean already gone."""
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _params(role_arn, tag_key):
    return [{"ParameterKey": "ServiceRoleArn", "ParameterValue": role_arn},
            {"ParameterKey": "TagFilterKey", "ParameterValue": tag_key}]


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation DeploymentGroup naming a ServiceRoleArn with no such role fails and rolls back.

    CodeDeploy's exact refusal is graded and the rolled-back application is gone, while the same
    template with a usable role deploys a group carrying that role.
    """
    cfn = ctx.client("cloudformation")
    cd = ctx.client("codedeploy")
    tag_key = ctx.unique_name("sim2real-nomatch-")  # one Ec2TagFilter key for both stacks

    # Setup through IAM: the usable role of the positive control.
    good_role_arn = _create_service_role(ctx)
    _wait_role_usable_by_codedeploy(ctx, cd, good_role_arn)

    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfn-cd-badrole-ctrl-"), _template(),
                           Parameters=_params(good_role_arn, tag_key))
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    out = stack_outputs(cfn, good_id)
    good_dg = cd.get_deployment_group(applicationName=out["ApplicationName"],
                                      deploymentGroupName=out["DeploymentGroupName"])[
        "deploymentGroupInfo"]
    got = (good_dg["serviceRoleArn"], good_dg["ec2TagFilters"])
    want = (good_role_arn, [{"Key": tag_key, "Value": "none", "Type": "KEY_AND_VALUE"}])
    assert got == want, f"control deployment group {got!r}, expected {want!r}"

    partition = good_id.split(":")[1]
    bad_role = ctx.unique_name("sim2real-cfn-cd-noroleref-")
    bad_role_arn = f"arn:{partition}:iam::{ctx.account}:role/{bad_role}"
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfn-cd-badrole-test-"), _template(),
                          Parameters=_params(bad_role_arn, tag_key))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"invalid-role stack ended {status!r}"
    events = stack_events(cfn, bad_id)
    got = handler_reason(failed_reason(events, "CDDeploymentGroup"), ctx.account, bad_role)
    want = (f"AWS CodeDeploy does not have the permissions required to assume the role "
            f"arn:{partition}:iam::<account>:role/<name>. (Service: CodeDeploy, Status Code: 400, "
            "Request ID: <id>) (SDK Attempt Count: <n>)", "InvalidRequest")
    assert got == want, f"handler reason {got!r}, expected {want!r}"

    # Rollback absence through CodeDeploy, before any delete: the application it created.
    created = [e["PhysicalResourceId"] for e in events
               if e["LogicalResourceId"] == "CDApplication" and e["ResourceStatus"] == "CREATE_COMPLETE"]
    assert len(created) == 1, f"CDApplication CREATE_COMPLETE rows: {created!r}"
    application_gone = (
        "ApplicationDoesNotExistException",
        f"No application found for name: {created[0]}",
    )
    expect_error(lambda: cd.get_application(applicationName=created[0]), *application_gone)


def _create_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cfn-cd-badrole-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codedeploy.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": role_name}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    partition = role_arn.split(":")[1]
    policy_arn = f"arn:{partition}:iam::aws:policy/service-role/AWSCodeDeployRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(_teardown(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn), "NoSuchEntity"))
    return role_arn


def _wait_role_usable_by_codedeploy(ctx, cd, service_role_arn: str, timeout_s: float = 90.0) -> None:
    """Cycle a throwaway application + deployment group through the role, to clear the
    IAM-propagation window CloudFormation (which does not retry) would otherwise race."""
    probe_app = ctx.unique_name("sim2real-cfn-cd-badrole-roleprobe-")
    cd.create_application(applicationName=probe_app, computePlatform="Server",
                          tags=[{"Key": "sim2real", "Value": probe_app}])
    ctx.on_cleanup(lambda: _drop_application(cd, probe_app))
    try:
        probe_group = ctx.unique_name("sim2real-cfn-cd-badrole-roleprobe-dg-")
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                cd.create_deployment_group(
                    applicationName=probe_app,
                    deploymentGroupName=probe_group,
                    serviceRoleArn=service_role_arn,
                    ec2TagFilters=[
                        {"Key": ctx.unique_name("sim2real-roleprobe-"), "Value": "none", "Type": "KEY_AND_VALUE"}
                    ],
                )
                break
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "InvalidRoleException" or time.monotonic() > deadline:
                    raise
                time.sleep(3)
        cd.delete_deployment_group(applicationName=probe_app, deploymentGroupName=probe_group)
    finally:
        _drop_application(cd, probe_app)


def _drop_application(cd, name):
    """Delete a probe application; only its exact absence counts as already done."""
    try:
        cd.delete_application(applicationName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ApplicationDoesNotExistException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
