"""create-workspace-invalid-org-units-combo-accepted."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-workspace-invalid-org-units-combo-accepted"
GROUP = "data-plane"
SERVICES = ["grafana"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateWorkspace accepts organizationalUnits with accountAccessType CURRENT_ACCOUNT, and
    DescribeWorkspace returns both exactly as given.
    """
    grafana = ctx.client("grafana")

    # Adopt-and-remove any workspace orphaned by a previous run of THIS check under this exact
    # literal prefix (e.g. a crash between CreateWorkspace succeeding and cleanup registration).
    # Scoped to this check's own naming convention only -- never a prefix shared with other checks.
    for stale in _list_all_workspaces(ctx):
        if stale.get("name", "").startswith("sim2real-behav-badcombo-"):
            _delete_workspace_cleanup(ctx, stale["id"])

    role_cleanup, role_arn = _create_grafana_workspace_role(ctx)
    name = ctx.unique_name("sim2real-behav-badcombo-")
    params = {
        "accountAccessType": "CURRENT_ACCOUNT",
        "permissionType": "SERVICE_MANAGED",
        "authenticationProviders": ["SAML"],
        "workspaceName": name,
        "workspaceRoleArn": role_arn,
        "workspaceOrganizationalUnits": ["ou-abcd-12345678"],
        "tags": {"sim2real:managed": "true"},
    }
    try:
        workspace = _create_workspace_call_with_retry(grafana, params)["workspace"]
    except Exception:
        # CreateWorkspace never got a workspace back, so only the role needs cleanup -- and it
        # needs it now, since nothing below will register it.
        role_cleanup()
        raise
    workspace_id = workspace["id"]
    # workspace_cleanup registered BEFORE role_cleanup so LIFO runs the free, fast role delete
    # FIRST and spends the shared 60s ctx.on_cleanup budget on the slow workspace teardown last
    # (an AMG workspace routinely takes minutes to settle; registering role_cleanup first would
    # starve it of that budget on every run).
    ctx.on_cleanup(lambda: _delete_workspace_cleanup(ctx, workspace_id))
    ctx.on_cleanup(role_cleanup)

    described = grafana.describe_workspace(workspaceId=workspace_id)["workspace"]
    assert described["accountAccessType"] == "CURRENT_ACCOUNT", (
        f"expected accountAccessType=CURRENT_ACCOUNT, got {described.get('accountAccessType')!r}"
    )
    assert described.get("organizationalUnits") == ["ou-abcd-12345678"], (
        "expected workspaceOrganizationalUnits to round-trip verbatim via DescribeWorkspace even "
        f"under CURRENT_ACCOUNT, got {described.get('organizationalUnits')!r}"
    )


def _list_all_workspaces(ctx):
    grafana = ctx.client("grafana")
    out = []
    token = None
    while True:
        kwargs = {"nextToken": token} if token else {}
        resp = grafana.list_workspaces(**kwargs)
        out.extend(resp["workspaces"])
        token = resp.get("nextToken")
        if not token:
            return out


def _create_grafana_workspace_role(ctx):
    """Returns (cleanup_fn, role_arn); the caller registers cleanup so it controls LIFO order."""
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
