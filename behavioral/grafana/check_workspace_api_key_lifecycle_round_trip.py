"""workspace-api-key-lifecycle-round-trip."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "workspace-api-key-lifecycle-round-trip"
GROUP = "data-plane"
SERVICES = ["grafana"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """A CreateWorkspaceApiKey secret authenticates against the workspace's Grafana HTTP API; after
    DeleteWorkspaceApiKey the secret is refused there and a second delete raises
    ResourceNotFoundException with the exact message.
    """
    grafana = ctx.client("grafana")

    workspace = _create_workspace(ctx)
    workspace_id = workspace["id"]
    active = _wait_for_workspace_status(ctx, workspace_id, {"ACTIVE"})
    endpoint = active["endpoint"]

    key_name = ctx.unique_name("sim2real-behav-key-")
    created = grafana.create_workspace_api_key(
        workspaceId=workspace_id, keyName=key_name, keyRole="ADMIN", secondsToLive=3600
    )
    assert created["keyName"] == key_name
    secret = created["key"]
    assert secret  # server-generated secret, opaque but must be non-empty

    # positive control: the freshly issued key actually authenticates at the destination — proves
    # "usable", which a non-empty-string check cannot
    org = _poll_grafana_api(f"{ctx.endpoint_url(endpoint)}/api/org", secret, timeout_s=180.0)
    assert "id" in org and "name" in org, f"unexpected Grafana /api/org payload: {org}"

    # positive control: the key we just created can be deleted successfully
    grafana.delete_workspace_api_key(workspaceId=workspace_id, keyName=key_name)

    # independent read at the destination: the deleted key no longer authenticates against the
    # native Grafana HTTP API, not just against the AWS control plane
    _poll_grafana_api_rejects(f"{ctx.endpoint_url(endpoint)}/api/org", secret, timeout_s=120.0)

    # negative: deleting the same (now-gone) key again is rejected, proving deletion is not a no-op
    code, message = _error(
        lambda: grafana.delete_workspace_api_key(workspaceId=workspace_id, keyName=key_name)
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a second delete of {key_name!r}, got {code!r}"
    )
    expected = f"API key {key_name} not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


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


def _poll_grafana_api_rejects(url: str, bearer_token: str, timeout_s: float = 120.0, interval_s: float = 5.0) -> None:
    """Waits out revocation propagation to the workspace's own auth layer, then demands the deleted
    key be refused there too — a bare AWS-side delete response is not proof the secret stopped working."""
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {bearer_token}"})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                last_status = resp.status
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                return
            last_status = exc.code
        except (urllib.error.URLError, TimeoutError) as exc:
            last_status = str(exc)
        time.sleep(interval_s)
    raise AssertionError(
        f"deleted API key still authenticated against {url} after {timeout_s}s (last status={last_status})"
    )


def _error(fn):
    """Call fn(); return its (error code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


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
        Tags=[{"Key": "sim2real", "Value": "true"}],
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
        "tags": {"sim2real": "true"},
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
