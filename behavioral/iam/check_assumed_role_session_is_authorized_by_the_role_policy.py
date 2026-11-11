"""assumed-role-session-is-authorized-by-the-role-policy."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assumed-role-session-is-authorized-by-the-role-policy"
GROUP = 'role_lifecycle'
SERVICES = ['iam']

_DENY_ALL_ARN = "arn:aws:iam::aws:policy/AWSDenyAll"
_ALLOW_POLICY = "sim2real-behav-rsess-allow-list"


# An AccessDenied ends with a pointer to a server-minted, per-request authorization id, given
# twice (in a console URL and on its own); every other character is pinned.
_AUTHZ_TAIL = (
    r"\. Go to https://[a-z0-9-]+\.console\.aws\.amazon\.com/iam/home\?region=[a-z0-9-]+"
    r"#/authorization-details/(\w+) for complete details, or call the GetRequestAuthorizationDetails "
    r"API with the following authorization id: \1"
)


def _expected_denial(message, head):
    """``head`` followed by the authorization-details pointer that ends ``message``: the pointer's
    region and per-request authorization id are the only parts read back from it."""
    found = re.search(_AUTHZ_TAIL + r"\Z", message or "")
    return head + (found.group(0) if found else ". Go to <authorization-details pointer>")


def _budget_s(ctx, cap_s):
    """A poll's timeout, bounded by the runner's remaining time so the poll fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


def _error_code(fn):
    """The captured AWS error code, or a sentinel that cannot be mistaken for one on success."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return "UNEXPECTED_SUCCESS"


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not reached within {timeout_s}s; last observation {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


def _trust_account_root(account_id):
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "sts:AssumeRole",
        }],
    })


def _assume(sts, role_arn, session_name, *, timeout_s=90.0, interval_s=3.0):
    """AssumeRole against a just-created role transiently 403s until the trust policy propagates.

    IAM exposes no API that reports a trust policy as effective, so the wait is the bounded
    AccessDenied retry itself -- the one place a propagation wait is legitimate.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
        except ClientError as exc:
            last = exc.response.get("Error", {}).get("Code")
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"could not assume {role_arn} within {timeout_s}s; last error {last!r}"
                ) from exc
            time.sleep(interval_s)


def _client_for_session(ctx, creds, service="iam"):
    """A client for ``service`` on this target, signing AS the minted session principal."""
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _denial_message(fn):
    """Error.Message of a call real AWS refuses; an unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Message") or ""
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


@tags(
    "axis:rejection",
    "concern:negative-classes",
    "plane:control",
    "cap:c7",
)
def run(ctx) -> None:
    """A session from sts:AssumeRole is authorized by its role's policy alone: the deny-all role's
    session gets AccessDenied with the exact message while the allow-scoped role's session succeeds
    at the same call, and each session's GetCallerIdentity ARN names its assumed role."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    trust = _trust_account_root(account_id)

    role_deny = ctx.unique_name("sim2real-behav-rsess-deny-")
    iam.create_role(
        RoleName=role_deny,
        AssumeRolePolicyDocument=trust,
        Path="/",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_deny))
    iam.attach_role_policy(RoleName=role_deny, PolicyArn=_DENY_ALL_ARN)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_deny, PolicyArn=_DENY_ALL_ARN)
    )
    # A named dependency, asserted rather than silently worked around: "the emulator ships no
    # AWS-managed policies" is itself a fidelity gap.
    attached = iam.list_attached_role_policies(RoleName=role_deny)["AttachedPolicies"]
    assert [p["PolicyArn"] for p in attached] == [_DENY_ALL_ARN], (
        f"the AWS-managed {_DENY_ALL_ARN} must be attached to {role_deny!r} before its session is "
        f"probed; ListAttachedRolePolicies reported {attached!r}"
    )

    role_allow = ctx.unique_name("sim2real-behav-rsess-allow-")
    role_allow_arn = iam.create_role(
        RoleName=role_allow,
        AssumeRolePolicyDocument=trust,
        Path="/",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_allow))
    iam.put_role_policy(
        RoleName=role_allow,
        PolicyName=_ALLOW_POLICY,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "iam:ListAttachedRolePolicies",
                "Resource": role_allow_arn,
            }],
        }),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_allow, PolicyName=_ALLOW_POLICY)
    )

    allow_creds = _assume(
        sts, role_allow_arn, "sim2real-behav-rsess-allow", timeout_s=_budget_s(ctx, 90.0)
    )
    deny_creds = _assume(
        sts,
        iam.get_role(RoleName=role_deny)["Role"]["Arn"],
        "sim2real-behav-rsess-deny",
        timeout_s=_budget_s(ctx, 90.0),
    )

    # --- Both sessions must provably BE their own role, not the harness's identity leaking through.
    allow_arn = _client_for_session(ctx, allow_creds, "sts").get_caller_identity()["Arn"]
    assert allow_arn.startswith(f"arn:aws:sts::{account_id}:assumed-role/{role_allow}/"), (
        f"the allow session must be an assumed-role principal for {role_allow!r}; "
        f"GetCallerIdentity returned {allow_arn!r}"
    )
    deny_arn = _client_for_session(ctx, deny_creds, "sts").get_caller_identity()["Arn"]
    assert deny_arn.startswith(f"arn:aws:sts::{account_id}:assumed-role/{role_deny}/"), (
        f"the deny session must be an assumed-role principal for {role_deny!r}; "
        f"GetCallerIdentity returned {deny_arn!r}"
    )

    # --- Positive control: the allow-scoped session succeeds, and returns the grant that permitted
    #     it, so the operation itself is demonstrably reachable for a session principal. The role's
    #     permission policy replicates per-replica after AssumeRole already succeeded on the trust
    #     policy, and IAM reports neither as effective, so this is a bounded poll on the granted call
    #     and raises rather than skipping if it never converges.
    as_allow = _client_for_session(ctx, allow_creds)
    permitted = _poll(
        lambda: _try_list_attached(as_allow, role_allow),
        lambda r: r[0] == "OK",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the allow role's inline grant becomes effective for its session",
    )
    assert permitted[0] == "OK", (
        f"the allow role grants iam:ListAttachedRolePolicies on itself, so its session must succeed; "
        f"got {permitted[0]!r}"
    )
    assert permitted[1] == [], (
        f"{role_allow!r} carries an INLINE policy only, so its attached-policy list must be empty "
        f"while the call itself succeeds; got {permitted[1]!r}"
    )

    # --- The identical operation, one variable changed: which role the session came from.
    as_deny = _client_for_session(ctx, deny_creds)
    denied = _error_code(lambda: as_deny.list_attached_role_policies(RoleName=role_allow))
    denied_msg = _denial_message(
        lambda: as_deny.list_attached_role_policies(RoleName=role_allow)
    )
    assert "is not authorized to perform: iam:ListAttachedRolePolicies" in denied_msg, (
        f"the denial must name the refused action iam:ListAttachedRolePolicies; got {denied_msg!r}"
    )
    assert denied_msg == _expected_denial(denied_msg, (
        f"User: {deny_arn} is not authorized to perform: iam:ListAttachedRolePolicies on resource: "
        f"role {role_allow} with an explicit deny in an identity-based policy: {_DENY_ALL_ARN}"
    )), f"expected the exact AccessDenied message AWS returns, got {denied_msg!r}"
    assert denied == "AccessDenied", (
        f"a session from a role carrying only {_DENY_ALL_ARN} must be refused with exactly "
        f"AccessDenied on the operation the other session just completed; got {denied!r}"
    )

    # --- The allow session still works after the denial, so the difference is the role policy.
    again = _poll(
        lambda: _error_code(lambda: as_allow.list_attached_role_policies(RoleName=role_allow)),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the allow session still succeeds after the deny session's refusal",
    )
    assert again == "UNEXPECTED_SUCCESS", (
        f"the allow session must still succeed after the deny session's refusal; got {again!r}"
    )


def _try_list_attached(client, role_name):
    """(code_or_OK, attached_policy_list_or_None) -- one probe, two observations."""
    try:
        return "OK", client.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
