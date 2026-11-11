"""missing-iam-permission-create-workspace-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "missing-iam-permission-create-workspace-rejected"
GROUP = "overly-permissive"
SERVICES = ["grafana"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An IAM principal with no attached policies (implicit deny) gets AccessDeniedException from
    CreateWorkspace, and no workspace is created under that failed attempt, while the operator's
    own (permitted) credentials can still create a workspace normally."""
    role_arn = _create_powerless_role(ctx)
    powerless_grafana = _assume_role_client(ctx, role_arn, "grafana")

    bad_name = ctx.unique_name("sim2real-behav-noperm-")
    # Fresh role-session credentials can read as an unknown token for a few seconds; retry only
    # that propagation error, bounded, before grading the refusal.
    deadline = time.monotonic() + 60.0
    while True:
        err = _error(lambda: powerless_grafana.create_workspace(
            accountAccessType="CURRENT_ACCOUNT",
            permissionType="SERVICE_MANAGED",
            authenticationProviders=["SAML"],
            workspaceName=bad_name,
        ))
        if err[0] != "UnrecognizedClientException" or time.monotonic() >= deadline:
            break
        time.sleep(3.0)
    account_id = role_arn.split(":")[4]
    role_name = role_arn.rsplit("/", 1)[1]
    expected = (
        "AccessDeniedException",
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/sim2real-behav is not authorized "
        f"to perform: grafana:CreateWorkspace on resource: arn:aws:grafana:{ctx.region}:{account_id}:"
        f"/workspaces because no identity-based policy allows the grafana:CreateWorkspace action",
    )
    assert err == expected, f"expected {expected!r}, got {err!r}"

    names = {w.get("name") for w in _list_all_workspaces(ctx)}
    assert bad_name not in names, "a workspace was created despite the caller lacking permission"

    # positive control: the operator's own credentials can perform the same action, and the
    # created workspace is independently visible at the destination, not just in the create response
    good = _create_workspace(ctx)
    good_names = {w.get("name") for w in _list_all_workspaces(ctx)}
    assert good["name"] in good_names, (
        f"the operator's own credentials created {good['name']!r}, but it is not visible "
        f"in an independent list_workspaces read: {good_names!r}"
    )


def _error(fn):
    """Call fn(); return its (Error.Code, Error.Message). A call that succeeds raises: an
    emulator accepting what AWS refuses must fail loudly, not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_powerless_role(ctx) -> str:
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "sts:AssumeRole",
        }],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _assume_role_client(ctx, role_arn: str, service: str):
    sts = ctx.client("sts")
    deadline = time.monotonic() + 30.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-behav")["Credentials"]
            return ctx.client(
                service,
                creds={
                    "aws_access_key_id": creds["AccessKeyId"],
                    "aws_secret_access_key": creds["SecretAccessKey"],
                    "aws_session_token": creds["SessionToken"],
                },
            )
        except ClientError as exc:
            last_exc = exc
            time.sleep(2.0)
    raise AssertionError(f"could not assume freshly created role {role_arn}: {last_exc}")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
