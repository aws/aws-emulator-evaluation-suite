"""update-workspace-conflict-while-updating-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-workspace-conflict-while-updating-rejected"
GROUP = "overly-permissive"
SERVICES = ["grafana"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateWorkspace returns UPDATING, a second update in flight raises ConflictException with the
    exact message and only the first description persists; a later update applies normally.
    """
    grafana = ctx.client("grafana")

    workspace = _create_workspace(ctx)
    workspace_id = workspace["id"]
    _wait_for_workspace_status(ctx, workspace_id, {"ACTIVE"})

    # The conflict is probed on a workspace read UPDATING right before it; an update the target
    # already applied is followed by a fresh one (bounded).
    seen = []
    for attempt in range(3):
        first_description = f"behav-first-update-{attempt}"
        first = grafana.update_workspace(
            workspaceId=workspace_id, workspaceDescription=first_description
        )["workspace"]
        assert first["status"] == "UPDATING", (
            f"positive control failed: expected the first UpdateWorkspace to report UPDATING, "
            f"got {first['status']!r}"
        )
        status = grafana.describe_workspace(workspaceId=workspace_id)["workspace"]["status"]
        if status == "UPDATING":
            break
        seen.append(status)
        _wait_for_workspace_status(ctx, workspace_id, {"ACTIVE"})
    else:
        raise AssertionError(f"the workspace was never read UPDATING after UpdateWorkspace: {seen!r}")

    code, message = _error(lambda: grafana.update_workspace(
        workspaceId=workspace_id, workspaceDescription="behav-second-update"
    ))
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    expected = "Workspace operation failed. Workspace is currently in the UPDATING state."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    settled = _wait_for_workspace_status(ctx, workspace_id, {"ACTIVE"})
    assert settled["description"] == first_description, (
        "the rejected concurrent update's value leaked into the final state: "
        f"{settled['description']!r}"
    )

    # restore: once the workspace is no longer mid-update, an identical UpdateWorkspace call is
    # no longer in conflict with anything and must succeed -- the earlier rejection was specific
    # to the in-flight state, not a general lockout of this workspace.
    third = grafana.update_workspace(
        workspaceId=workspace_id, workspaceDescription="behav-third-update"
    )["workspace"]
    assert third["status"] == "UPDATING", (
        f"expected a fresh UpdateWorkspace to be accepted once the workspace had settled to "
        f"ACTIVE, got {third['status']!r}"
    )
    final = _wait_for_workspace_status(ctx, workspace_id, {"ACTIVE"})
    assert final["description"] == "behav-third-update", (
        "the identical UpdateWorkspace call did not persist once the workspace was no longer "
        f"mid-update: settled description is {final['description']!r}"
    )


def _error(fn):
    """Call fn(); return its (error code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected the concurrent UpdateWorkspace to be rejected, but it SUCCEEDED: {result!r}"
    )


def _create_grafana_workspace_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "grafana.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy),
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


def _create_workspace_call_with_retry(grafana, params, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return grafana.create_workspace(**params)
        except ClientError as exc:
            msg = exc.response["Error"].get("Message", "")
            if exc.response["Error"]["Code"] == "ValidationException" and "Workspace Role" in msg:
                # freshly created IAM role not yet visible/assumable by the Grafana service
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _create_workspace(ctx, **overrides):
    grafana = ctx.client("grafana")
    params = {
        "accountAccessType": "CURRENT_ACCOUNT",
        "permissionType": "SERVICE_MANAGED",
        "authenticationProviders": ["SAML"],
        "workspaceName": ctx.unique_name("sim2real-behav-"),
        "tags": {"sim2real": CHECK},
    }
    params.update(overrides)
    if params.get("accountAccessType") == "CURRENT_ACCOUNT" and "workspaceRoleArn" not in params:
        params["workspaceRoleArn"] = _create_grafana_workspace_role(ctx)
    workspace = _create_workspace_call_with_retry(grafana, params)["workspace"]
    workspace_id = workspace["id"]
    ctx.on_cleanup(lambda: _delete_workspace_cleanup(ctx, workspace_id))
    return workspace


def _delete_workspace_cleanup(ctx, workspace_id) -> None:
    grafana = ctx.client("grafana")
    stable = {
        "ACTIVE", "FAILED", "CREATION_FAILED", "UPDATE_FAILED", "UPGRADE_FAILED",
        "DELETION_FAILED", "LICENSE_REMOVAL_FAILED", "VERSION_UPDATE_FAILED", "DEGRADED",
    }
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        try:
            ws = grafana.describe_workspace(workspaceId=workspace_id)["workspace"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if ws["status"] in stable:
            break
        time.sleep(10)
    try:
        grafana.delete_workspace(workspaceId=workspace_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("ResourceNotFoundException", "ConflictException"):
            return
        raise
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        try:
            grafana.describe_workspace(workspaceId=workspace_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(10)


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
