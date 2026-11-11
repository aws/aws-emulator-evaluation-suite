"""service-account-lifecycle-round-trip."""

from __future__ import annotations

import datetime
import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "service-account-lifecycle-round-trip"
GROUP = "data-plane"
SERVICES = ["grafana"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A workspace service account and its token are created, appear in the list APIs with the
    correct attributes (including a token expiry computed from secondsToLive), and disappear
    from those same lists once deleted."""
    grafana = ctx.client("grafana")

    workspace = _create_workspace(ctx)
    workspace_id = workspace["id"]
    _wait_for_workspace_status(ctx, workspace_id, {"ACTIVE"})

    account = grafana.create_workspace_service_account(
        workspaceId=workspace_id, name=ctx.unique_name("sim2real-behav-sa-"), grafanaRole="EDITOR"
    )
    account_id = account["id"]
    assert account["grafanaRole"] == "EDITOR", (
        f"expected grafanaRole=EDITOR, got {account['grafanaRole']}"
    )

    # ListWorkspaceServiceAccounts echoes grafanaRole title-cased ("Editor"), not the request's
    # all-caps enum value ("EDITOR") that CreateWorkspaceServiceAccount itself echoes back above —
    # confirmed on real AWS, so the comparison here is case-insensitive rather than a literal match.
    accounts = grafana.list_workspace_service_accounts(workspaceId=workspace_id)["serviceAccounts"]
    assert any(a["id"] == account_id and a["grafanaRole"].upper() == "EDITOR" for a in accounts), (
        f"created service account {account_id} not visible with grafanaRole=EDITOR in {accounts}"
    )

    seconds_to_live = 3600
    before_create = datetime.datetime.now(datetime.timezone.utc)
    token = grafana.create_workspace_service_account_token(
        workspaceId=workspace_id,
        serviceAccountId=account_id,
        name=ctx.unique_name("sim2real-behav-tok-"),
        secondsToLive=seconds_to_live,
    )
    token_id = token["serviceAccountToken"]["id"]
    assert token["serviceAccountToken"]["key"], (
        "CreateWorkspaceServiceAccountToken returned no secret key"
    )

    tokens = grafana.list_workspace_service_account_tokens(
        workspaceId=workspace_id, serviceAccountId=account_id
    )["serviceAccountTokens"]
    listed = next(t for t in tokens if t["id"] == token_id)
    expected_expiry = before_create + datetime.timedelta(seconds=seconds_to_live)
    delta = abs((listed["expiresAt"] - expected_expiry).total_seconds())
    assert delta < 120, (
        f"expiresAt {listed['expiresAt']} not within 2 minutes of expected {expected_expiry}"
    )

    grafana.delete_workspace_service_account_token(
        workspaceId=workspace_id, serviceAccountId=account_id, tokenId=token_id
    )
    tokens_after = grafana.list_workspace_service_account_tokens(
        workspaceId=workspace_id, serviceAccountId=account_id
    )["serviceAccountTokens"]
    assert all(t["id"] != token_id for t in tokens_after), (
        f"deleted token {token_id} still listed in {tokens_after}"
    )
    # deletion is not a no-op: the same token id must now be rejected, not silently accepted again
    token_err = _error(
        lambda: grafana.delete_workspace_service_account_token(
            workspaceId=workspace_id, serviceAccountId=account_id, tokenId=token_id
        )
    )
    token_expected = (
        "ResourceNotFoundException",
        f"Service Account Token with id={token_id} does not exist.",
    )
    assert token_err == token_expected, (
        f"deleting already-deleted token {token_id}: expected {token_expected!r}, got {token_err!r}"
    )

    grafana.delete_workspace_service_account(workspaceId=workspace_id, serviceAccountId=account_id)
    accounts_after = grafana.list_workspace_service_accounts(workspaceId=workspace_id)[
        "serviceAccounts"
    ]
    assert all(a["id"] != account_id for a in accounts_after), (
        f"deleted service account {account_id} still listed in {accounts_after}"
    )
    # same double-delete proof for the service account itself
    account_err = _error(
        lambda: grafana.delete_workspace_service_account(
            workspaceId=workspace_id, serviceAccountId=account_id
        )
    )
    account_expected = (
        "ResourceNotFoundException",
        f"Service Account with id={account_id} does not exist.",
    )
    assert account_err == account_expected, (
        f"deleting already-deleted service account {account_id}: expected {account_expected!r}, got {account_err!r}"
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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
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
        "ACTIVE",
        "FAILED",
        "CREATION_FAILED",
        "UPDATE_FAILED",
        "UPGRADE_FAILED",
        "DELETION_FAILED",
        "LICENSE_REMOVAL_FAILED",
        "VERSION_UPDATE_FAILED",
        "DEGRADED",
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
