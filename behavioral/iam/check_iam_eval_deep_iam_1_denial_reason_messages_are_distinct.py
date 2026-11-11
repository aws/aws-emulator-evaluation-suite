"""iam-eval-deep-iam-1-denial-reason-messages-are-distinct."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "iam-eval-deep-iam-1-denial-reason-messages-are-distinct"
GROUP = 'policy_evaluation_denied'
SERVICES = ['iam']

_POLICY = "sim2real-behav-denial-identity"
_ROLE_POLICY = "sim2real-behav-denial-role"
_SESSION_NAME = "sim2real-denial-session"
# Credential-propagation states: a fresh key or session is not yet known to every replica.
_PROPAGATION = frozenset({"InvalidClientTokenId", "SignatureDoesNotMatch"})
# Real AWS appends a per-request pointer to GetRequestAuthorizationDetails after the reason
# clause. It carries a server-minted id, so it is matched by shape and never pinned.
_AUTHZ_TAIL = re.compile(
    r"\. Go to https://\S+ for complete details, or call the GetRequestAuthorizationDetails "
    r"API with the following authorization id: [A-Za-z0-9]+"
)


def _outcome(fn, settle_s=60):
    """("OK", None) on success, else (error code, error message).

    Only credential-propagation codes are retried (bounded): a fresh key flickers
    InvalidClientTokenId across IAM replicas. Every other code is returned on first sight.
    """
    deadline = time.monotonic() + settle_s
    while True:
        try:
            fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") in _PROPAGATION and time.monotonic() < deadline:
                time.sleep(2)
                continue
            return err.get("Code"), err.get("Message", "")
        return "OK", None


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


def _streak_ok(call, *, n=3, timeout_s=120, description):
    """Poll until `call` (an _outcome thunk) succeeds `n` times IN A ROW. Measured on real IAM:
    a first success can be followed by a stale replica refusing the same grant, so one success
    is not a propagation barrier."""
    run = {"n": 0}

    def step():
        run["n"] = run["n"] + 1 if call() == ("OK", None) else 0
        return run["n"]

    return _poll(step, lambda k: k >= n, timeout_s=timeout_s, interval_s=2,
                 description=description)


def _first_settled(probe, *, description):
    """First observation that is neither a credential-propagation state nor a success.

    A success means the deny has not reached this replica yet, so it is polled through (bounded).
    """
    return _poll(
        probe,
        lambda o: o[0] not in _PROPAGATION and o[0] != "OK",
        timeout_s=60,
        interval_s=3,
        description=description,
    )


def _with_authorization_details(base, message):
    """IAM's access-denied text: ``base`` followed by a pointer to the per-request authorization
    id, the one opaque token read back from the message; the console link names us-east-1."""
    region = "us-east-1"
    marker = "authorization id: "
    auth_id = message.rsplit(marker, 1)[-1] if message and marker in message else "<absent>"
    return (
        f"{base}. Go to https://{region}.console.aws.amazon.com/iam/home?region={region}"
        f"#/authorization-details/{auth_id} for complete details, or call the "
        f"GetRequestAuthorizationDetails API with the following authorization id: {auth_id}"
    )


def _reason(message, head):
    """Split an AccessDenied message into the reason clause after `head`, dropping the tail."""
    assert message.startswith(head), (
        f"AccessDenied message must start with {head!r}; got {message!r}"
    )
    rest = message[len(head):]
    m = _AUTHZ_TAIL.search(rest)
    if m is not None:
        assert m.end() == len(rest), (
            f"text follows the authorization-details pointer in {message!r}"
        )
        rest = rest[: m.start()]
    return rest


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c7")
def run(ctx) -> None:
    """Four AccessDenied causes on iam:GetUser yield four distinct exact reason clauses: no allow,
    identity-policy deny, permissions-boundary deny (naming its ARN), and session-policy deny;
    each principal first passes a positive control.

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_access-denied.html
    """
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    def _user_arn(name):
        return f"arn:aws:iam::{account}:user/{name}"

    # Targets: one per denial cause, plus a control target every principal may read.
    targets = {}
    for label in ("ctl", "none", "ident", "bound", "sess"):
        name = ctx.unique_name(f"sim2real-behav-den-{label}-")
        iam.create_user(UserName=name, Tags=[{"Key": "sim2real", "Value": CHECK}])
        ctx.on_cleanup(lambda n=name: iam.delete_user(UserName=n))
        targets[label] = name

    # The boundary: allows everything except iam:GetUser on the boundary target.
    boundary_arn = iam.create_policy(
        PolicyName=ctx.unique_name("sim2real-behav-den-boundary-"),
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "*", "Resource": "*"},
                {"Effect": "Deny", "Action": "iam:GetUser",
                 "Resource": _user_arn(targets["bound"])},
            ],
        }),
        Description="sim2real denial-reason boundary",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=boundary_arn))

    # The minted principal, bounded at creation so the boundary predates every grant.
    user = ctx.unique_name("sim2real-behav-den-caller-")
    iam.create_user(UserName=user, PermissionsBoundary=boundary_arn,
                    Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user))
    ctx.on_cleanup(lambda: iam.delete_user_permissions_boundary(UserName=user))
    stored = iam.get_user(UserName=user)["User"].get("PermissionsBoundary", {})
    assert stored.get("PermissionsBoundaryArn") == boundary_arn, (
        f"the boundary must be attached before anything is concluded from it; got {stored!r}"
    )

    role = ctx.unique_name("sim2real-behav-den-role-")
    role_arn = f"arn:aws:iam::{account}:role/{role}"
    iam.put_user_policy(
        UserName=user,
        PolicyName=_POLICY,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                # Allowed here: ctl, bound (the boundary then denies), ident (explicitly denied
                # below). NOT allowed anywhere: none.
                {"Effect": "Allow", "Action": "iam:GetUser",
                 "Resource": [_user_arn(targets[t]) for t in ("ctl", "bound", "ident")]},
                {"Effect": "Deny", "Action": "iam:GetUser",
                 "Resource": _user_arn(targets["ident"])},
                {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": role_arn},
            ],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user, PolicyName=_POLICY))

    # Same-account trust delegated to identity policy: the account root as principal, so the
    # minted user's own sts:AssumeRole grant is what admits it.
    iam.create_role(
        RoleName=role,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role))
    iam.put_role_policy(
        RoleName=role,
        PolicyName=_ROLE_POLICY,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "iam:GetUser",
                           "Resource": [_user_arn(targets["ctl"]),
                                        _user_arn(targets["sess"])]}],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role, PolicyName=_ROLE_POLICY))

    key = iam.create_access_key(UserName=user)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user, AccessKeyId=key["AccessKeyId"]))
    user_creds = {"aws_access_key_id": key["AccessKeyId"],
                  "aws_secret_access_key": key["SecretAccessKey"]}
    as_user = ctx.client("iam", creds=user_creds)

    # Positive control for the user: the grant on the control target is live.
    _streak_ok(
        lambda: _outcome(lambda: as_user.get_user(UserName=targets["ctl"])),
        description="the minted user's iam:GetUser grant on the control target becomes effective",
    )
    ctl_user = _outcome(lambda: as_user.get_user(UserName=targets["ctl"]))
    assert ctl_user == ("OK", None), f"control GetUser as the minted user failed: {ctl_user!r}"

    user_arn = _user_arn(user)
    head = "User: {p} is not authorized to perform: iam:GetUser on resource: user {t} "
    observed = {}

    for label, expected in (
        ("none", "because no identity-based policy allows the iam:GetUser action"),
        ("ident", "with an explicit deny in an identity-based policy"),
        ("bound", f"with an explicit deny in a permissions boundary: {boundary_arn}"),
    ):
        code, message = _first_settled(
            lambda t=targets[label]: _outcome(lambda: as_user.get_user(UserName=t)),
            description=f"a denial of iam:GetUser on the {label!r} target",
        )
        assert code == "AccessDenied", (
            f"GetUser on the {label!r} target must be refused with exactly AccessDenied; "
            f"got {code!r}: {message!r}"
        )
        reason = _reason(message, head.format(p=user_arn, t=targets[label]))
        assert reason == expected, (
            f"the {label!r} denial must carry the reason clause {expected!r}; got {reason!r} "
            f"(full message {message!r})"
        )
        expected_message = _with_authorization_details(
            head.format(p=user_arn, t=targets[label]) + expected, message)
        assert message == expected_message, (
            f"expected message {expected_message!r}, got {message!r}"
        )
        observed[label] = reason

    # The session: the same minted user assumes the role with a session policy that allows
    # everything except iam:GetUser on the session target.
    as_user_sts = ctx.client("sts", creds=user_creds)
    session_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
            {"Effect": "Deny", "Action": "iam:GetUser", "Resource": _user_arn(targets["sess"])},
        ],
    })
    assumed_box = []

    def _assume():
        assumed_box.append(as_user_sts.assume_role(
            RoleArn=role_arn, RoleSessionName=_SESSION_NAME, Policy=session_policy,
            DurationSeconds=900))

    assumed = _poll(
        lambda: _outcome(_assume),
        lambda o: o[0] == "OK",
        timeout_s=120, interval_s=3,
        description="the minted user may assume the role (identity grant + new role propagate)",
    )
    assert assumed == ("OK", None) and assumed_box, (
        f"AssumeRole as the minted user failed: {assumed!r}"
    )
    assumed_box = assumed_box[-1:]
    sess = assumed_box[0]["Credentials"]
    as_session = ctx.client("iam", creds={
        "aws_access_key_id": sess["AccessKeyId"],
        "aws_secret_access_key": sess["SecretAccessKey"],
        "aws_session_token": sess["SessionToken"],
    })
    session_arn = assumed_box[0]["AssumedRoleUser"]["Arn"]
    assert session_arn == f"arn:aws:sts::{account}:assumed-role/{role}/{_SESSION_NAME}", (
        f"unexpected assumed-role ARN {session_arn!r}"
    )

    _streak_ok(
        lambda: _outcome(lambda: as_session.get_user(UserName=targets["ctl"])),
        description="the role session's iam:GetUser grant on the control target is effective",
    )
    ctl_sess = _outcome(lambda: as_session.get_user(UserName=targets["ctl"]))
    assert ctl_sess == ("OK", None), (
        f"control GetUser as the role session failed — the session policy must narrow, not "
        f"revoke: {ctl_sess!r}"
    )
    code, message = _first_settled(
        lambda: _outcome(lambda: as_session.get_user(UserName=targets["sess"])),
        description="a session-policy denial of iam:GetUser on the session target",
    )
    assert code == "AccessDenied", (
        f"GetUser on the session target must be refused with exactly AccessDenied; "
        f"got {code!r}: {message!r}"
    )
    reason = _reason(message, head.format(p=session_arn, t=targets["sess"]))
    assert reason == "with an explicit deny in a session policy", (
        f"the session denial must carry 'with an explicit deny in a session policy'; got "
        f"{reason!r} (full message {message!r})"
    )
    expected_message = _with_authorization_details(
        head.format(p=session_arn, t=targets["sess"]) + reason, message)
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    observed["sess"] = reason

    # The four reason clauses are pairwise distinct: no cause is reported as another.
    clauses = list(observed.values())
    assert len(clauses) == 4 and len(set(clauses)) == 4, (
        f"the four denial reasons must be pairwise distinct; got {observed!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
