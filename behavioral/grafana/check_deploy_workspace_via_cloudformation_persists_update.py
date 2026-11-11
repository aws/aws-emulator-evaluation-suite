"""deploy-workspace-via-cloudformation-persists-update."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-workspace-via-cloudformation-persists-update"
GROUP = "deploy"
SERVICES = ["grafana"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:deploy",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """An AWS::Grafana::Workspace stack reaches CREATE_COMPLETE with the workspace ACTIVE and its
    description, a direct UpdateWorkspace persists, and deleting the stack removes the workspace
    (Describe and Update not found).
    """
    grafana = ctx.client("grafana")
    cfn = ctx.client("cloudformation")

    workspace_id, stack_name = _deploy_workspace_stack(
        ctx, description="behav-cfn-initial-description"
    )

    active = _wait_for_workspace_status(ctx, workspace_id, {"ACTIVE"})
    assert active["description"] == "behav-cfn-initial-description", (
        f"CFN-created workspace description mismatch: expected 'behav-cfn-initial-description', "
        f"got {active['description']!r}"
    )

    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"stack {stack_name} status: expected CREATE_COMPLETE, got {stack['StackStatus']}"
    )
    resource = cfn.describe_stack_resources(
        StackName=stack_name, LogicalResourceId="GrafanaWorkspace"
    )["StackResources"][0]
    assert resource["PhysicalResourceId"] == workspace_id, (
        f"stack resource PhysicalResourceId mismatch: expected {workspace_id}, "
        f"got {resource['PhysicalResourceId']}"
    )
    assert resource["ResourceStatus"] == "CREATE_COMPLETE", (
        f"stack resource status: expected CREATE_COMPLETE, got {resource['ResourceStatus']}"
    )

    # the control plane is not CFN-exclusive: a direct UpdateWorkspace call still persists
    grafana.update_workspace(workspaceId=workspace_id, workspaceDescription="behav-direct-update")
    settled = _wait_for_workspace_status(ctx, workspace_id, {"ACTIVE"})
    assert settled["description"] == "behav-direct-update", (
        f"direct UpdateWorkspace did not persist: expected description 'behav-direct-update', "
        f"got {settled['description']!r}"
    )

    # deleting the stack tears down the underlying workspace too
    _delete_stack_and_wait(ctx, stack_name)
    gone = (
        "ResourceNotFoundException",
        f"Workspace with id={workspace_id} of account={ctx.account} does not exist.",
    )
    err = _error(lambda: grafana.describe_workspace(workspaceId=workspace_id))
    assert err == gone, (
        f"the workspace survived its own owning CloudFormation stack being deleted: expected {gone!r}, got {err!r}"
    )

    # gone means unusable too: a mutation on the dead id must fail the same way, not silently no-op
    update_err = _error(
        lambda: grafana.update_workspace(
            workspaceId=workspace_id, workspaceDescription="post-delete-update"
        )
    )
    assert update_err == gone, (
        f"UpdateWorkspace on a workspace deleted with its owning stack: expected {gone!r}, got {update_err!r}"
    )


def _error(fn):
    """Call fn(); return its (Error.Code, Error.Message). A call that succeeds raises: an
    emulator accepting what AWS refuses must fail loudly, not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _create_grafana_workspace_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "grafana.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_cleanup(iam, role_name))
    return role_arn


def _delete_role_cleanup(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _deploy_workspace_stack(ctx, description: str):
    cfn = ctx.client("cloudformation")
    role_arn = _create_grafana_workspace_role(ctx)
    stack_name = ctx.unique_name("sim2real-behav-stack-")
    workspace_name = ctx.unique_name("sim2real-behav-")
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "GrafanaWorkspace": {
                "Type": "AWS::Grafana::Workspace",
                "Properties": {
                    "AccountAccessType": "CURRENT_ACCOUNT",
                    "AuthenticationProviders": ["SAML"],
                    "PermissionType": "SERVICE_MANAGED",
                    "RoleArn": role_arn,
                    "Name": workspace_name,
                    "Description": description,
                },
            }
        },
        "Outputs": {"WorkspaceId": {"Value": {"Ref": "GrafanaWorkspace"}}},
    }
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        OnFailure="DELETE",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack_name))
    _wait_for_stack_status(
        ctx, stack_name, {"CREATE_COMPLETE"}, {"ROLLBACK_COMPLETE", "CREATE_FAILED"}
    )
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return outputs["WorkspaceId"], stack_name


def _wait_for_stack_status(
    ctx, stack_name, targets, failure_states, timeout_s=900.0, interval_s=15.0
):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        last_status = stack["StackStatus"]
        if last_status in targets:
            return stack
        if last_status in failure_states:
            raise AssertionError(f"stack {stack_name} entered failure state {last_status}")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} never reached {targets}; last status={last_status}")


def _delete_stack_and_wait(ctx, stack_name, timeout_s=900.0, interval_s=15.0) -> None:
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ValidationError":
            return
        raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ValidationError":
                return
            raise
        if stack["StackStatus"] == "DELETE_COMPLETE":
            return
        if stack["StackStatus"] == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} DELETE_FAILED")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} was never deleted")


def _wait_for_workspace_status(ctx, workspace_id, targets, timeout_s=600.0, interval_s=15.0):
    grafana = ctx.client("grafana")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        ws = grafana.describe_workspace(workspaceId=workspace_id)["workspace"]
        last = ws
        if ws["status"] in targets:
            return ws
        time.sleep(interval_s)
    raise AssertionError(
        f"workspace {workspace_id} never reached {targets}; last status="
        f"{last['status'] if last else None}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
