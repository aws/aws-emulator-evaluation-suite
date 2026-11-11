"""assumed-role-sees-the-same-account-state."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assumed-role-sees-the-same-account-state"
GROUP = "identity"
SERVICES = ["iam", "ssm", "sts"]

ASSUME_TIMEOUT_S = 180.0
PERMISSION_TIMEOUT_S = 180.0


@tags("axis:happy-path", "cap:c7", "concern:e2e", "plane:control")
def run(ctx) -> None:
    """A role assumed in the same account reports that account and a distinct assumed-role ARN, and
    reads an SSM parameter the base identity wrote: assuming a role changes the principal, not state.

    Reference: https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
    """
    sts = ctx.client("sts")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")

    base_identity = sts.get_caller_identity()
    account = base_identity["Account"]

    # --- Beat 1: write state under the BASE identity ----------------------------------------------
    param_name = ctx.unique_name("/sim2real-behav-identity/")
    param_value = ctx.unique_name("value-")
    ssm.put_parameter(Name=param_name, Value=param_value, Type="String")
    ctx.on_cleanup(lambda: _delete_param(ssm, param_name))
    assert ssm.get_parameter(Name=param_name)["Parameter"]["Value"] == param_value, (
        "setup: the base identity must be able to read what it just wrote"
    )

    # --- Beat 2: a role in THIS account, assumable by it ------------------------------------------
    role_name = ctx.unique_name("sim2real-behav-idrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="read-the-parameter",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["ssm:GetParameter"], "Resource": "*"}
                ],
            }
        ),
    )

    # --- Beat 3: the assumed identity is a DIFFERENT principal in the SAME account -----------------
    session = ctx.unique_name("sim2real-behav-id-")
    assumed = _assume(sts, role_arn, session)
    creds = {
        "aws_access_key_id": assumed["AccessKeyId"],
        "aws_secret_access_key": assumed["SecretAccessKey"],
        "aws_session_token": assumed["SessionToken"],
    }
    assumed_identity = ctx.client("sts", creds=creds).get_caller_identity()
    assert assumed_identity["Account"] == account, (
        f"a role assumed inside account {account!r} must report that account, got "
        f"{assumed_identity['Account']!r}. This is the half a fresh-empty-partition target still gets "
        f"right, which is why Beat 4 exists"
    )
    assert assumed_identity["Arn"] != base_identity["Arn"], (
        f"the assumed caller must be a DIFFERENT principal from the base one; both reported "
        f"{base_identity['Arn']!r}, so nothing was actually assumed"
    )
    partition = role_arn.split(":")[1]
    want_arn = f"arn:{partition}:sts::{ctx.account}:assumed-role/{role_name}/{session}"
    assert assumed_identity["Arn"] == want_arn, (
        f"the assumed caller's ARN: expected {want_arn!r}, got {assumed_identity['Arn']!r}"
    )

    # --- Beat 4: and it sees the state the base identity wrote ------------------------------------
    assumed_ssm = ctx.client("ssm", creds=creds)
    value = _read_with_permission_retry(assumed_ssm, param_name)
    assert value == param_value, (
        f"the assumed role must read the value the base identity wrote ({param_value!r}), got "
        f"{value!r}. A not-found here means the assumed credential landed in a different world -- "
        f"the resource exists and the policy allows it"
    )

    # --- Teardown in reverse dependency order, each proven gone ------------------------------------
    _gone_assumable_role(ctx, role_name, role_arn)
    _gone_parameter(ctx, param_name)


def _assume(sts, role_arn: str, session: str) -> dict:
    """AssumeRole, polled until the new role's trust policy propagates; raises on timeout."""
    deadline = time.monotonic() + ASSUME_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(
                RoleArn=role_arn, RoleSessionName=session
            )["Credentials"]
        except ClientError as exc:
            last = exc
            time.sleep(3.0)
    raise AssertionError(f"could not assume {role_arn!r} within {ASSUME_TIMEOUT_S}s: {last}")


def _read_with_permission_retry(ssm, name: str) -> str:
    """GetParameter as the assumed role, retrying only AccessDenied while its permissions propagate;
    ParameterNotFound fails at once, since it is the defect under test.
    """
    deadline = time.monotonic() + PERMISSION_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        try:
            return ssm.get_parameter(Name=name)["Parameter"]["Value"]
        except ssm.exceptions.AccessDeniedException as exc:
            last = exc
            time.sleep(3.0)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            raise AssertionError(
                f"the assumed role's GetParameter for {name!r} failed with {code!r}: "
                f"{exc.response.get('Error', {}).get('Message')!r}. The parameter exists and the "
                f"role policy allows ssm:GetParameter, so a not-found means the assumed "
                f"credential is reading a different world"
            ) from exc
    raise AssertionError(
        f"the role's ssm:GetParameter permission never propagated within {PERMISSION_TIMEOUT_S}s: "
        f"{last}"
    )


def _delete_param(ssm, name: str) -> None:
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if _err(exc)[0] != "ParameterNotFound":
            raise


def _delete_role(iam, role_name: str) -> None:
    """Inline policies must go before the role itself, or DeleteRole fails DeleteConflict."""
    try:
        for policy in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy)
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if _err(exc)[0] != "NoSuchEntity":
            raise


#: Deadline for a delete to reach its terminal not-found answer.
_GONE_S = 120.0


def _err(exc: ClientError) -> tuple[str, int, str]:
    """(code, HTTP status, message) of a ClientError."""
    e = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return e.get("Code") or "", status, e.get("Message") or e.get("message") or ""


def _refused(fn, codes: tuple[str, ...], status: int, what: str, message: str) -> None:
    """``fn()`` must fail with one of ``codes`` at ``status`` and exactly ``message``; SSM's own
    not-found answers carry an empty one."""
    try:
        fn()
    except ClientError as exc:
        code, got, msg = _err(exc)
        assert code in codes and got == status, (
            f"{what}: expected {'/'.join(codes)} HTTP {status}, got {code!r} HTTP {got!r}: {msg[:150]!r}"
        )
        assert msg == message, f"{what}: {code} message: expected {message!r}, got {msg!r}"
        return
    raise AssertionError(f"{what}: expected {'/'.join(codes)} HTTP {status}, the call succeeded")


def _poll_refused(fn, codes, status, what, message, timeout_s: float = _GONE_S) -> None:
    """Poll ``fn`` until it reaches the terminal not-found answer, then grade it with ``_refused``.

    A success while the delete converges is retried; any other error fails at once.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            code, _, _ = _err(exc)
            if code in codes:
                _refused(fn, codes, status, what, message)
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what}: still readable {timeout_s:.0f}s after the delete")
        time.sleep(1.0)


def _tolerant(fn, *codes: str):
    """A teardown that ignores only the given not-found codes (the body already deleted it)."""

    def run() -> None:
        try:
            fn()
        except ClientError as exc:
            if _err(exc)[0] not in codes:
                raise

    return run


def _paged(client, op: str, key: str, **kw) -> list:
    """Every element of ``key`` across all pages of ``op``."""
    out: list = []
    for page in client.get_paginator(op).paginate(**kw):
        out.extend(page.get(key, []))
    return out



def _gone_assumable_role(ctx, name: str, arn: str) -> None:
    """Delete the role; GetRole NoSuchEntity, ListRoles lacks it, PutRolePolicy refused."""
    iam = ctx.client("iam")
    for p in iam.list_role_policies(RoleName=name)["PolicyNames"]:
        iam.delete_role_policy(RoleName=name, PolicyName=p)
    iam.delete_role(RoleName=name)
    nf = ("NoSuchEntity",)
    not_found = f"The role with name {name} cannot be found."
    _poll_refused(lambda: iam.get_role(RoleName=name), nf, 404, f"GetRole {name}", not_found)
    listed = {r["RoleName"] for r in _paged(iam, "list_roles", "Roles", PathPrefix="/")}
    assert name not in listed, f"ListRoles still lists deleted role {name}"
    doc = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ssm:GetParameter","Resource":"*"}]}'
    _refused(
        lambda: iam.put_role_policy(RoleName=name, PolicyName="gone", PolicyDocument=doc),
        nf, 404, f"PutRolePolicy {name}", not_found,
    )


def _gone_parameter(ctx, name: str) -> None:
    """Delete the parameter; GetParameter ParameterNotFound, DescribeParameters empty, tagging refused."""
    ssm = ctx.client("ssm")
    ssm.delete_parameter(Name=name)
    _poll_refused(
        lambda: ssm.get_parameter(Name=name), ("ParameterNotFound",), 400,
        f"GetParameter {name}", "",
    )
    found = ssm.describe_parameters(
        ParameterFilters=[{"Key": "Name", "Option": "Equals", "Values": [name]}]
    ).get("Parameters", [])
    assert not found, f"DescribeParameters(Name Equals) still returns deleted parameter {name}"
    _refused(
        lambda: ssm.add_tags_to_resource(
            ResourceType="Parameter", ResourceId=name, Tags=[{"Key": "gone", "Value": "x"}]
        ),
        ("InvalidResourceId",), 400, f"AddTagsToResource {name}", "",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
