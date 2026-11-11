"""grafana-http-api-native-round-trip."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "grafana-http-api-native-round-trip"
GROUP = "native-protocol"
SERVICES = ["grafana"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A workspace service-account token authenticates against the workspace's own Grafana HTTP API,
    and GET /api/org returns an org payload with id and name.
    """
    grafana = ctx.client("grafana")

    workspace = _create_workspace(ctx)
    workspace_id = workspace["id"]
    active = _wait_for_workspace_status(ctx, workspace_id, {"ACTIVE"})
    endpoint = active["endpoint"]

    account = grafana.create_workspace_service_account(
        workspaceId=workspace_id, name=ctx.unique_name("sim2real-behav-sa-"), grafanaRole="ADMIN"
    )
    token = grafana.create_workspace_service_account_token(
        workspaceId=workspace_id,
        serviceAccountId=account["id"],
        name=ctx.unique_name("sim2real-behav-tok-"),
        secondsToLive=3600,
    )
    key = token["serviceAccountToken"]["key"]

    org = _poll_grafana_api(f"{ctx.endpoint_url(endpoint)}/api/org", key, timeout_s=180.0)
    assert "id" in org and "name" in org, f"unexpected Grafana /api/org payload: {org}"


def _poll_grafana_api(url: str, bearer_token: str, timeout_s: float = 180.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {bearer_token}"})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status == 200:
                    return json.loads(resp.read().decode("utf-8"))
                last_error = AssertionError(f"unexpected HTTP status {resp.status}")
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
            last_error = exc
        time.sleep(interval_s)
    raise AssertionError(f"Grafana HTTP API at {url} never returned 200: {last_error}")


def _create_grafana_workspace_role(ctx) -> tuple[str, str]:
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
    return role_arn, role_name


def _delete_role_cleanup(iam, role_name: str) -> None:
    try:
        for policy in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy["PolicyArn"])
        for policy_name in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
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
    role_name = None
    if params.get("accountAccessType") == "CURRENT_ACCOUNT" and "workspaceRoleArn" not in params:
        params["workspaceRoleArn"], role_name = _create_grafana_workspace_role(ctx)
    workspace = _create_workspace_call_with_retry(grafana, params)["workspace"]
    workspace_id = workspace["id"]
    # ctx.on_cleanup runs LIFO, so register the slow workspace teardown FIRST and the fast role
    # delete LAST: the workspace teardown below polls for up to 1200s and can exceed the
    # runner's 60s cleanup budget, which would strand a role cleanup queued behind it.
    ctx.on_cleanup(lambda: _delete_workspace_cleanup(ctx, workspace_id))
    if role_name is not None:
        ctx.on_cleanup(lambda: _delete_role_cleanup(ctx.client("iam"), role_name))
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
