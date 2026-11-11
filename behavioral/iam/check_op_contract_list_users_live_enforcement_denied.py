"""op-contract-list-users-live-enforcement-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

CHECK = "op-contract-list-users-live-enforcement-denied"
GROUP = "error-semantics"
SERVICES = ["iam"]


from behavioral_harness import tags


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListUsers with a PathPrefix reports the created user; a role session's real signed
    ListUsers fails with AccessDenied and the exact message once an explicit Deny is attached
    and succeeds again once it is removed, while the check's own caller keeps listing users."""
    iam = ctx.client("iam")

    path = f"/{ctx.unique_name('sim2real-lu')}/"
    name = ctx.unique_name("sim2real-user-")
    arn = iam.create_user(
        UserName=name, Path=path, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["User"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=name))

    resp = iam.list_users(PathPrefix=path)
    matches = [u for u in resp["Users"] if u["UserName"] == name]
    assert len(matches) == 1, resp["Users"]
    assert matches[0]["Arn"] == arn

    as_role, iam_as_role, session_arn = _assume_allow_all_role(ctx)

    # --- Positive control, captured BEFORE anything is broken: with only the broad Allow in
    #     place, the real signed ListUsers must succeed for this exact principal and wiring.
    before_code, _ = _poll_for_code(lambda: as_role.list_users(PathPrefix=path))
    assert before_code is None, (
        f"with only the Allow in place, the assumed role's real signed ListUsers must succeed; "
        f"got error code {before_code!r}"
    )

    # --- Break exactly ONE thing: an inline Deny naming iam:ListUsers and nothing else.
    deny_policy = "deny-list-users"
    iam.put_role_policy(
        RoleName=iam_as_role,
        PolicyName=deny_policy,
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "iam:ListUsers", "Resource": "*"}]}
        ),
    )
    ctx.on_cleanup(lambda: _drop_deny(iam, iam_as_role, deny_policy))

    denied_code, denied_message = _poll_for_code(
        lambda: as_role.list_users(PathPrefix=path), want="AccessDenied"
    )
    assert denied_code == "AccessDenied", f"expected AccessDenied, got {denied_code!r}"
    account_id = arn.split(":")[4]
    expected = (
        f"User: {session_arn} is not authorized to perform: iam:ListUsers on resource: "
        f"arn:aws:iam::{account_id}:user{path} with an explicit deny in an identity-based policy"
    )
    assert denied_message == expected, f"expected message {expected!r}, got {denied_message!r}"

    # positive control: the original principal's access is unaffected by a Deny scoped to the
    # other role
    resp2 = iam.list_users(PathPrefix=path)
    assert any(u["UserName"] == name for u in resp2["Users"])

    # --- Reverse the one change: the effect must be reversible, so the denial was caused by
    #     the Deny and not by drift.
    iam.delete_role_policy(RoleName=iam_as_role, PolicyName=deny_policy)
    restored_code, _ = _poll_for_code(lambda: as_role.list_users(PathPrefix=path))
    assert restored_code is None, (
        f"deleting the Deny must restore the assumed role's real signed ListUsers; got error "
        f"code {restored_code!r}"
    )


def _assume_allow_all_role(ctx):
    """Create a role trusted by this account, grant it a broad Allow, assume it, and return
    (client-as-role, role_name, assumed-role session ARN) — the client comes from ctx.client, so
    it is pinned to the same endpoint ctx uses and the emulator arm exercises the emulator's own
    authorizer rather than falling through to real AWS."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-deny-role-")
    trust_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_doc),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    allow_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="allow-all", PolicyDocument=json.dumps(allow_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="allow-all"))

    deadline = time.monotonic() + 90.0
    creds = None
    last_err = None
    while time.monotonic() < deadline and creds is None:
        try:
            resp = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-deny-test")
            creds = resp["Credentials"]
            session_arn = resp["AssumedRoleUser"]["Arn"]
        except ClientError as exc:
            last_err = exc
            time.sleep(2.0)
    if creds is None:
        raise AssertionError(f"could not assume deny-role within timeout: {last_err}")

    as_role = ctx.client(
        "iam",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    return as_role, role_name, session_arn


def _drop_deny(iam, role_name, policy_name):
    """Teardown-only: the body deletes this policy itself, so tolerate it already being gone."""
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _poll_for_code(fn, want=None, timeout_s: float = 90.0, interval_s: float = 3.0):
    """Poll for a call to settle into the wanted state: ``want=None`` means "succeeds with no
    error", ``want="SomeCode"`` means that error code specifically. Returns (code, message);
    raises on timeout rather than returning a value the caller could mistake for success."""
    deadline = time.monotonic() + timeout_s
    last = "UNEXPECTED_SUCCESS"
    while time.monotonic() < deadline:
        message = None
        try:
            fn()
            last = None
        except ClientError as exc:
            last = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message")
        if last == want:
            return last, message
        time.sleep(interval_s)
    raise AssertionError(f"did not converge on {want!r} within {timeout_s}s; last observed {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
