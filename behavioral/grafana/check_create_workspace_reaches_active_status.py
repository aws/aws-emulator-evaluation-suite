"""create-workspace-reaches-active-status."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-workspace-reaches-active-status"
GROUP = "lifecycle"
SERVICES = ["grafana"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateWorkspace returns CREATING and the async provisioning state machine settles on ACTIVE."""
    grafana = ctx.client("grafana")

    workspace = _create_workspace(ctx)
    workspace_id = workspace["id"]
    # CreateWorkspace's HTTP contract returns 202 with the workspace already CREATING.
    assert workspace["status"] == "CREATING", f"expected CREATING, got {workspace['status']}"

    active = _wait_for_workspace_status(ctx, workspace_id, {"ACTIVE"})
    assert active["accountAccessType"] == "CURRENT_ACCOUNT", (
        f"expected accountAccessType=CURRENT_ACCOUNT, got {active['accountAccessType']}"
    )
    assert active["permissionType"] == "SERVICE_MANAGED", (
        f"expected permissionType=SERVICE_MANAGED, got {active['permissionType']}"
    )
    assert active["authentication"]["providers"] == ["SAML"], (
        f"expected authentication providers=[SAML], got {active['authentication']['providers']}"
    )
    assert active["endpoint"], f"expected a non-empty endpoint, got {active.get('endpoint')!r}"

    ids = {w["id"] for w in grafana.list_workspaces()["workspaces"]}
    assert workspace_id in ids, "newly created workspace is not visible via ListWorkspaces"


def _create_grafana_workspace_role(ctx):
    """Returns (cleanup_fn, role_arn). The caller registers cleanup itself, and registers it
    AFTER the workspace's own cleanup — ctx.run_cleanups() is LIFO and shares one bounded
    budget, so this free IAM role must be deleted before that budget is spent waiting on the
    workspace's (much slower) teardown, not after."""
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    return (lambda: _delete_role_cleanup(iam, role_name)), role_arn


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
        "tags": {"sim2real:managed": "true"},
    }
    params.update(overrides)
    role_cleanup = None
    if params.get("accountAccessType") == "CURRENT_ACCOUNT" and "workspaceRoleArn" not in params:
        role_cleanup, params["workspaceRoleArn"] = _create_grafana_workspace_role(ctx)
    workspace = _create_workspace_call_with_retry(grafana, params)["workspace"]
    workspace_id = workspace["id"]
    # Registered before role_cleanup so LIFO runs the free, fast role delete FIRST and spends
    # the shared cleanup budget on the slow workspace teardown last (see
    # _create_grafana_workspace_role's docstring).
    ctx.on_cleanup(lambda: _delete_workspace_cleanup(ctx, workspace_id))
    if role_cleanup is not None:
        ctx.on_cleanup(role_cleanup)
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
