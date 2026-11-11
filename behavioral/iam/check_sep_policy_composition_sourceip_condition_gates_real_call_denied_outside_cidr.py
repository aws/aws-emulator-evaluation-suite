"""sep-policy-composition-sourceip-condition-gates-real-call-denied-outside-cidr."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sep-policy-composition-sourceip-condition-gates-real-call-denied-outside-cidr"
GROUP = "policy_composition"
SERVICES = ["iam"]


# ===== helpers =====
def _error_code(fn):
    """The captured AWS error code, or a sentinel that cannot be mistaken for one on success."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return "UNEXPECTED_SUCCESS"


def _outcome(fn):
    """'OK' when the real signed call succeeds, else its exact AWS error code."""
    code = _error_code(fn)
    return "OK" if code == "UNEXPECTED_SUCCESS" else code


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


def _client_as(ctx, key_id, secret, token=None, service="iam"):
    """A client signing AS the minted principal."""
    creds = {"aws_access_key_id": key_id, "aws_secret_access_key": secret}
    if token:
        creds["aws_session_token"] = token
    return ctx.client(service, creds=creds)


def _settle(probe, want, *, description, streak=3, timeout_s=150, interval_s=2):
    """Poll until probe() returns `want` on `streak` CONSECUTIVE calls.

    IAM is eventually consistent and exposes no API that reports a grant as effective, so the
    operation is its own observable. A streak (rather than one hit) keeps a single lagging replica
    from being read as the steady state. Returns every observation, for the failure message.
    """
    deadline = time.monotonic() + timeout_s
    seen, run = [], 0
    while True:
        got = probe()
        seen.append(got)
        run = run + 1 if got == want else 0
        if run >= streak:
            return seen
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: wanted {want!r} {streak}x in a row within {timeout_s}s; "
                f"last observations {seen[-12:]!r}"
            )
        time.sleep(interval_s)


def _policy(*statements):
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


def _decisions(iam, source_arn, actions, resource_arns, **kw):
    results = iam.simulate_principal_policy(
        PolicySourceArn=source_arn, ActionNames=actions, ResourceArns=resource_arns, **kw
    )["EvaluationResults"]
    return {r["EvalActionName"]: r for r in results}


def _sim_settle(iam, source_arn, actions, resource_arns, want, *, description, **kw):
    """Poll the simulator until every action's EvalDecision equals `want[action]`."""
    last = {}

    def probe():
        nonlocal last
        last = _decisions(iam, source_arn, actions, resource_arns, **kw)
        return {a: last[a]["EvalDecision"] for a in actions}

    _settle(probe, want, description=description, streak=1)
    return last


def _purge_user(iam, user):
    """Undo everything a check may have hung on a user, then delete it."""
    for fn in (
        lambda: [iam.delete_user_policy(UserName=user, PolicyName=p)
                 for p in iam.list_user_policies(UserName=user)["PolicyNames"]],
        lambda: [iam.detach_user_policy(UserName=user, PolicyArn=p["PolicyArn"])
                 for p in iam.list_attached_user_policies(UserName=user)["AttachedPolicies"]],
        lambda: [iam.delete_access_key(UserName=user, AccessKeyId=k["AccessKeyId"])
                 for k in iam.list_access_keys(UserName=user)["AccessKeyMetadata"]],
        lambda: [iam.remove_user_from_group(UserName=user, GroupName=g["GroupName"])
                 for g in iam.list_groups_for_user(UserName=user)["Groups"]],
        lambda: iam.delete_user_permissions_boundary(UserName=user),
    ):
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise
    iam.delete_user(UserName=user)
# ===== end helpers =====


def _ip_ctx(ip):
    return [{"ContextKeyName": "aws:SourceIp", "ContextKeyValues": [ip], "ContextKeyType": "ip"}]


def _denial_message(fn):
    """Error.Message of a call real AWS refuses; an unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Message") or ""
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """aws:SourceIp is evaluated against the caller's real address: a call gated to TEST-NET-1 is
    AccessDenied, the simulator agrees for inside/outside/missing addresses, and widening the CIDR
    to 0.0.0.0/0 flips both views to allowed.
    """
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-sep-ip-")
    user_arn = iam.create_user(UserName=user)["User"]["Arn"]
    ctx.on_cleanup(lambda: _purge_user(iam, user))
    iam.put_user_policy(
        UserName=user, PolicyName="control",
        PolicyDocument=_policy({"Effect": "Allow", "Action": "iam:GetUser", "Resource": user_arn}),
    )

    def put_ip_policy(cidr):
        iam.put_user_policy(
            UserName=user, PolicyName="ip-gated",
            PolicyDocument=_policy({
                "Effect": "Allow", "Action": "iam:ListAccessKeys", "Resource": user_arn,
                "Condition": {"IpAddress": {"aws:SourceIp": cidr}},
            }),
        )

    put_ip_policy("192.0.2.0/24")
    key = iam.create_access_key(UserName=user)["AccessKey"]
    as_user = _client_as(ctx, key["AccessKeyId"], key["SecretAccessKey"])
    act = ["iam:ListAccessKeys"]
    inside, outside = "192.0.2.44", "198.51.100.7"

    # --- Simulator, three contexts.
    _sim_settle(iam, user_arn, act, [user_arn], {"iam:ListAccessKeys": "allowed"},
                description="simulator, source address inside 192.0.2.0/24",
                ContextEntries=_ip_ctx(inside))
    out_sim = _decisions(iam, user_arn, act, [user_arn], ContextEntries=_ip_ctx(outside))
    assert out_sim["iam:ListAccessKeys"]["EvalDecision"] == "implicitDeny", (
        f"{outside} is outside 192.0.2.0/24; simulator said {out_sim['iam:ListAccessKeys']!r}"
    )
    none_sim = _decisions(iam, user_arn, act, [user_arn])["iam:ListAccessKeys"]
    assert none_sim["EvalDecision"] == "implicitDeny", f"no context: {none_sim!r}"
    assert "aws:SourceIp" in none_sim.get("MissingContextValues", []), (
        f"with no address supplied the simulator must name aws:SourceIp as missing; got {none_sim!r}"
    )

    # --- Real call; RFC 5737 TEST-NET-1 is never a real client's source address.
    _settle(lambda: _outcome(lambda: as_user.get_user(UserName=user)), "OK",
            description="real GetUser positive control")
    denied = _outcome(lambda: as_user.list_access_keys(UserName=user))
    assert denied == "AccessDenied", (
        f"the runner's address is outside 192.0.2.0/24, so the IP-gated Allow cannot match and the "
        f"real call must be refused with exactly AccessDenied; got {denied!r}"
    )
    denied_msg = _denial_message(lambda: as_user.list_access_keys(UserName=user))
    expected_msg = _with_authorization_details(
        f"User: {user_arn} is not authorized to perform: iam:ListAccessKeys on resource: user "
        f"{user} because no identity-based policy allows the iam:ListAccessKeys action",
        denied_msg,
    )
    assert denied_msg == expected_msg, f"expected message {expected_msg!r}, got {denied_msg!r}"
    assert (out_sim["iam:ListAccessKeys"]["EvalDecision"] == "allowed") == (denied == "OK"), (
        f"simulator for an outside address {out_sim['iam:ListAccessKeys']['EvalDecision']!r} "
        f"disagrees with the real call {denied!r}"
    )

    # --- Widen only the CIDR: both views must flip for an outside address.
    put_ip_policy("0.0.0.0/0")
    _sim_settle(iam, user_arn, act, [user_arn], {"iam:ListAccessKeys": "allowed"},
                description="simulator for the outside address once the CIDR is 0.0.0.0/0",
                ContextEntries=_ip_ctx(outside))
    _settle(lambda: _outcome(lambda: as_user.list_access_keys(UserName=user)), "OK",
            description="real ListAccessKeys once the CIDR is 0.0.0.0/0")

    # --- Narrow back: this denial follows a proven-effective grant of the SAME statement, so it can
    # only be the CIDR -- not a grant that had not propagated yet.
    put_ip_policy("192.0.2.0/24")
    _settle(lambda: _outcome(lambda: as_user.list_access_keys(UserName=user)), "AccessDenied",
            description="real ListAccessKeys once the CIDR is narrowed back to TEST-NET-1")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
