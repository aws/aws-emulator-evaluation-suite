"""deploy-cfn-codedeploy-provisioning-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-codedeploy-provisioning-lifecycle"
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

def _template(with_group=True) -> str:
    template = (
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
                "CDDeploymentConfig": {
                    "Type": "AWS::CodeDeploy::DeploymentConfig",
                    "Properties": {"MinimumHealthyHosts": {"Type": "FLEET_PERCENT", "Value": 75}},
                },
            },
            "Outputs": {
                "ApplicationName": {"Value": {"Ref": "CDApplication"}},
                "DeploymentGroupName": {"Value": {"Ref": "CDDeploymentGroup"}},
                "DeploymentConfigName": {"Value": {"Ref": "CDDeploymentConfig"}},
            },
        }
    )
    if not with_group:
        del template["Resources"]["CDDeploymentGroup"]
        del template["Outputs"]["DeploymentGroupName"]
    return json.dumps(template)


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


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation CodeDeploy Application, DeploymentGroup and DeploymentConfig read back.

    Each Ref names an independently listed resource whose properties round-trip; an update
    dropping the group removes it while the application stays, and the stack delete the rest.
    """
    cfn = ctx.client("cloudformation")
    cd = ctx.client("codedeploy")

    # Setup through IAM: the group's usable service role.
    service_role_arn = _create_service_role(ctx)
    _wait_role_usable_by_codedeploy(ctx, cd, service_role_arn)
    tag_filter_key = ctx.unique_name("sim2real-nomatch-")
    params = [{"ParameterKey": "ServiceRoleArn", "ParameterValue": service_role_arn},
              {"ParameterKey": "TagFilterKey", "ParameterValue": tag_filter_key}]

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfn-cd-lifecycle-"), _template(),
                            Parameters=params)
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    app_ref, dg_ref, dc_ref = (out["ApplicationName"], out["DeploymentGroupName"],
                               out["DeploymentConfigName"])

    assert app_ref in paginate(cd, "list_applications", "applications"), f"{app_ref!r} not listed"
    groups = paginate(cd, "list_deployment_groups", "deploymentGroups", applicationName=app_ref)
    assert groups == [dg_ref], f"ListDeploymentGroups of {app_ref!r}: {groups!r}"
    assert dc_ref in paginate(cd, "list_deployment_configs", "deploymentConfigsList"), (
        f"{dc_ref!r} not listed"
    )

    got_app = cd.get_application(applicationName=app_ref)["application"]
    got = (got_app["applicationName"], got_app["computePlatform"])
    assert got == (app_ref, "Server"), f"GetApplication {got!r}, expected {(app_ref, 'Server')!r}"
    got_dg = cd.get_deployment_group(applicationName=app_ref, deploymentGroupName=dg_ref)[
        "deploymentGroupInfo"]
    got = (got_dg["applicationName"], got_dg["serviceRoleArn"], got_dg["ec2TagFilters"])
    want = (app_ref, service_role_arn,
            [{"Key": tag_filter_key, "Value": "none", "Type": "KEY_AND_VALUE"}])
    assert got == want, f"GetDeploymentGroup {got!r}, expected {want!r}"
    got_dc = cd.get_deployment_config(deploymentConfigName=dc_ref)["deploymentConfigInfo"]
    got = (got_dc["deploymentConfigName"], got_dc["minimumHealthyHosts"])
    assert got == (dc_ref, {"type": "FLEET_PERCENT", "value": 75}), f"GetDeploymentConfig {got!r}"

    # Child first: the update drops only the group; its own NotFound while the same
    # application (its createTime) still answers.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(with_group=False), Parameters=params)
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"group-dropping update ended {status!r}"
    after = cd.get_application(applicationName=app_ref)["application"]
    assert after["createTime"] == got_app["createTime"], f"the application after the update {after!r}"
    deployment_group_gone = (
        "DeploymentGroupDoesNotExistException",
        f"No Deployment Group found for name: {dg_ref}",
    )
    expect_error(lambda: cd.get_deployment_group(applicationName=app_ref, deploymentGroupName=dg_ref),
                 *deployment_group_gone)

    delete_stack(cfn, stack_id)
    application_gone = (
        "ApplicationDoesNotExistException",
        f"No application found for name: {app_ref}",
    )
    expect_error(lambda: cd.get_application(applicationName=app_ref), *application_gone)
    deployment_config_gone = (
        "DeploymentConfigDoesNotExistException",
        f"No deployment configuration found for name: {dc_ref}",
    )
    expect_error(lambda: cd.get_deployment_config(deploymentConfigName=dc_ref),
                 *deployment_config_gone)


def _create_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cfn-cd-role-")
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
    probe_app = ctx.unique_name("sim2real-cfn-cd-roleprobe-")
    cd.create_application(applicationName=probe_app, computePlatform="Server",
                          tags=[{"Key": "sim2real", "Value": probe_app}])
    ctx.on_cleanup(lambda: _drop_application(cd, probe_app))
    try:
        probe_group = ctx.unique_name("sim2real-cfn-cd-roleprobe-dg-")
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
