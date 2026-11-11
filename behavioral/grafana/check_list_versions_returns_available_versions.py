"""list-versions-returns-available-versions."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-versions-returns-available-versions"
GROUP = "control-plane"
SERVICES = ["grafana"]

_STABLE_STATUSES = {
    "ACTIVE", "FAILED", "CREATION_FAILED", "UPDATE_FAILED", "UPGRADE_FAILED",
    "DELETION_FAILED", "LICENSE_REMOVAL_FAILED", "VERSION_UPDATE_FAILED", "DEGRADED",
}


def _newest_version(versions: list[str]) -> str:
    def key(v: str):
        try:
            return (1, tuple(int(p) for p in v.split(".")))
        except ValueError:
            return (0, v)
    return max(versions, key=key)


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListVersions without a workspaceId returns a non-empty list of version strings, and a
    workspace created with the newest one becomes ACTIVE reporting that grafanaVersion.
    """
    grafana = ctx.client("grafana")
    resp = grafana.list_versions()
    versions = resp["grafanaVersions"]
    assert len(versions) > 0, "expected at least one available Grafana version"
    assert all(isinstance(v, str) and v for v in versions), (
        f"expected every catalog entry to be a non-empty string, got {versions}"
    )

    target_version = _newest_version(versions)
    workspace_id = _create_workspace(ctx, grafanaVersion=target_version)

    settled = _wait_for_stable_status(ctx, workspace_id)
    assert settled["status"] == "ACTIVE", (
        f"workspace pinned to catalog version {target_version!r} did not become ACTIVE, "
        f"landed in status {settled['status']!r}"
    )
    assert settled["grafanaVersion"] == target_version, (
        f"expected the active workspace to report catalog version {target_version!r}, "
        f"got {settled['grafanaVersion']!r}"
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "audit"}],
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


def _create_workspace(ctx, **overrides) -> str:
    grafana = ctx.client("grafana")
    params = {
        "accountAccessType": "CURRENT_ACCOUNT",
        "permissionType": "SERVICE_MANAGED",
        "authenticationProviders": ["SAML"],
        "workspaceName": ctx.unique_name("sim2real-behav-"),
        "tags": {"sim2real": "audit"},
    }
    params.update(overrides)
    if params.get("accountAccessType") == "CURRENT_ACCOUNT" and "workspaceRoleArn" not in params:
        params["workspaceRoleArn"] = _create_grafana_workspace_role(ctx)
    workspace = _create_workspace_call_with_retry(grafana, params)["workspace"]
    workspace_id = workspace["id"]
    ctx.on_cleanup(lambda: _delete_workspace_cleanup(ctx, workspace_id))
    return workspace_id


def _delete_workspace_cleanup(ctx, workspace_id) -> None:
    grafana = ctx.client("grafana")
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        try:
            ws = grafana.describe_workspace(workspaceId=workspace_id)["workspace"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if ws["status"] in _STABLE_STATUSES:
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


def _wait_for_stable_status(ctx, workspace_id, timeout_s=600.0, interval_s=15.0):
    grafana = ctx.client("grafana")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        ws = grafana.describe_workspace(workspaceId=workspace_id)["workspace"]
        last = ws
        if ws["status"] in _STABLE_STATUSES:
            return ws
        time.sleep(interval_s)
    raise AssertionError(
        f"workspace {workspace_id} never reached a stable status; last status="
        f"{last['status'] if last else None}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
