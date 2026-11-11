"""update-workspace-configuration-json-roundtrip."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-workspace-configuration-json-roundtrip"
GROUP = "data-plane"
SERVICES = ["grafana"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateWorkspaceConfiguration's JSON override round-trips through DescribeWorkspaceConfiguration."""
    grafana = ctx.client("grafana")

    workspace = _create_workspace(ctx)
    workspace_id = workspace["id"]
    _wait_for_workspace_status(ctx, workspace_id, {"ACTIVE"})

    baseline = grafana.describe_workspace_configuration(workspaceId=workspace_id)
    baseline_config = json.loads(baseline["configuration"])
    baseline_enabled = baseline_config.get("unifiedAlerting", {}).get("enabled", False)
    assert not baseline_enabled, (
        f"expected a freshly created workspace's unifiedAlerting.enabled to be falsy, "
        f"got {baseline_enabled!r}"
    )

    grafana.update_workspace_configuration(
        workspaceId=workspace_id,
        configuration=json.dumps({"unifiedAlerting": {"enabled": True}}),
    )
    _wait_for_workspace_status(ctx, workspace_id, {"ACTIVE"})

    updated = grafana.describe_workspace_configuration(workspaceId=workspace_id)
    updated_config = json.loads(updated["configuration"])
    updated_enabled = updated_config["unifiedAlerting"]["enabled"]
    assert updated_enabled is True, (
        f"expected DescribeWorkspaceConfiguration to reflect the UpdateWorkspaceConfiguration "
        f"override unifiedAlerting.enabled=True, got {updated_enabled!r}"
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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
        "tags": {"sim2real-check": CHECK},
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
