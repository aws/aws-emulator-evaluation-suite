"""delete-workspace-removes-resource-and-double-delete-conflicts."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-workspace-removes-resource-and-double-delete-conflicts"
GROUP = "lifecycle"
SERVICES = ["grafana"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteWorkspace returns DELETING, a second delete in flight returns the same workspace still
    DELETING (or not-found once the first has finished), and once it is gone DeleteWorkspace
    raises ResourceNotFoundException with the exact message.
    """
    grafana = ctx.client("grafana")

    workspace = _create_workspace(ctx)
    workspace_id = workspace["id"]
    _wait_for_workspace_status(ctx, workspace_id, {"ACTIVE"})

    deleting = grafana.delete_workspace(workspaceId=workspace_id)["workspace"]
    assert deleting["status"] == "DELETING", f"expected DELETING after DeleteWorkspace, got {deleting['status']!r}"

    # a second delete issued immediately is accepted idempotently while the first is still in
    # flight -- same workspace, still DELETING -- as AWS returns 202/DELETING here rather than
    # ConflictException; a target that already finished the first delete answers not-found
    expected_gone = f"Workspace with id={workspace_id} of account={ctx.account} does not exist."
    try:
        concurrent = grafana.delete_workspace(workspaceId=workspace_id)["workspace"]
    except ClientError as exc:
        code, message = exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        assert (code, message) == ("ResourceNotFoundException", expected_gone), (
            f"a re-delete must answer DELETING in flight or not-found once gone, got {code!r}: {message!r}"
        )
    else:
        assert concurrent["id"] == workspace_id, (
            f"idempotent re-delete returned a different workspace: {concurrent['id']!r} != {workspace_id!r}"
        )
        assert concurrent["status"] == "DELETING", (
            f"expected the concurrent delete to report DELETING idempotently, got {concurrent['status']!r}"
        )

    # positive control: the original delete keeps running and the workspace is eventually gone
    _wait_for_workspace_removal(ctx, workspace_id)

    # once actually gone, a further delete must report not-found, not the in-flight ConflictException
    code_after_removal, message = _error(lambda: grafana.delete_workspace(workspaceId=workspace_id))
    assert code_after_removal == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a delete on an already-removed workspace, "
        f"got {code_after_removal!r}"
    )
    expected = expected_gone
    assert message == expected, (
        f"expected message {expected!r} for a delete on an already-removed workspace, "
        f"got {message!r}"
    )


def _error(fn):
    """Call fn(); return its (error code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
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
        "tags": {"sim2real-behav": CHECK},
    }
    params.update(overrides)
    if params.get("accountAccessType") == "CURRENT_ACCOUNT" and "workspaceRoleArn" not in params:
        params["workspaceRoleArn"] = _create_grafana_workspace_role(ctx)
    workspace = _create_workspace_call_with_retry(grafana, params)["workspace"]
    workspace_id = workspace["id"]
    ctx.on_cleanup(lambda: _delete_workspace_cleanup(ctx, workspace_id))
    return workspace


def _wait_for_workspace_removal(ctx, workspace_id, timeout_s=600.0, interval_s=10.0) -> None:
    grafana = ctx.client("grafana")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            grafana.describe_workspace(workspaceId=workspace_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"workspace {workspace_id} was never removed after DeleteWorkspace")


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
