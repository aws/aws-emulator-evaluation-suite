"""service-account-token-seconds-to-live-out-of-range-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "service-account-token-seconds-to-live-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["grafana"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateWorkspaceServiceAccountToken rejects secondsToLive outside the documented 1..2592000
    range; the rejected call leaves no token behind, while a request with a valid value succeeds
    and shows up in ListWorkspaceServiceAccountTokens."""
    grafana = ctx.client("grafana")

    workspace = _create_workspace(ctx)
    workspace_id = workspace["id"]
    _wait_for_workspace_status(ctx, workspace_id, {"ACTIVE"})

    account = grafana.create_workspace_service_account(
        workspaceId=workspace_id, name=ctx.unique_name("sim2real-behav-sa-"), grafanaRole="VIEWER"
    )
    account_id = account["id"]

    bad_name = ctx.unique_name("sim2real-behav-tok-bad-")
    code, message = _error(lambda: grafana.create_workspace_service_account_token(
        workspaceId=workspace_id,
        serviceAccountId=account_id,
        name=bad_name,
        secondsToLive=2_592_001,  # one second over the documented maximum
    ))
    # Real AWS answers this specific constraint violation with the unmodeled BadRequestException,
    # not the ValidationException the CreateWorkspaceServiceAccountToken Smithy shape declares.
    assert code == "BadRequestException", (
        f"expected BadRequestException for secondsToLive=2592001, got {code!r}"
    )
    assert message == "Invalid request body", (
        f"expected message 'Invalid request body' for secondsToLive=2592001, got {message!r}"
    )

    tokens = grafana.list_workspace_service_account_tokens(
        workspaceId=workspace_id, serviceAccountId=account_id
    )["serviceAccountTokens"]
    assert all(t["name"] != bad_name for t in tokens), "an out-of-range token was created anyway"

    # positive control: a valid secondsToLive succeeds and is listed
    good_name = ctx.unique_name("sim2real-behav-tok-good-")
    good = grafana.create_workspace_service_account_token(
        workspaceId=workspace_id, serviceAccountId=account_id, name=good_name, secondsToLive=3600
    )
    tokens_after = grafana.list_workspace_service_account_tokens(
        workspaceId=workspace_id, serviceAccountId=account_id
    )["serviceAccountTokens"]
    assert any(t["id"] == good["serviceAccountToken"]["id"] for t in tokens_after), (
        f"token {good['serviceAccountToken']['id']} for {good_name!r} not found in "
        f"ListWorkspaceServiceAccountTokens: {tokens_after!r}"
    )


def _error(fn):
    """Call fn(); return its botocore (error code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"secondsToLive=2592001 exceeds the documented 1..2592000 range but the call "
        f"succeeded and returned {result!r}"
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
