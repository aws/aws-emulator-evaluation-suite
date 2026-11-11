"""sep-policy-composition-securetransport-condition-denied-when-policy-requires-plaintext."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sep-policy-composition-securetransport-condition-denied-when-policy-requires-plaintext"
GROUP = "policy_composition"
SERVICES = ["iam"]
_MARK = [{"Key": "sim2real", "Value": CHECK}]


# ----- helpers -----
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


def _refusal(fn):
    """``(code, message)`` of a call real AWS refuses; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS refuses this call, but it succeeded and returned {result!r}")


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
    """A client signing AS the minted principal, wired to the same target as every other client."""
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
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
    iam.delete_user(UserName=user)
# ----- end helpers -----


def _tls_ctx(value):
    return [{"ContextKeyName": "aws:SecureTransport", "ContextKeyValues": [value],
             "ContextKeyType": "boolean"}]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """aws:SecureTransport reflects the real transport, and the simulator predicts the real call:
    an Allow conditioned on a plaintext connection must deny a TLS request in both views, through a
    rewrite to Allow-unconditionally plus Deny-if-plaintext and back again.
    """
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-sep-tls-")
    user_arn = iam.create_user(UserName=user, Tags=_MARK)["User"]["Arn"]
    ctx.on_cleanup(lambda: _purge_user(iam, user))
    iam.put_user_policy(
        UserName=user, PolicyName="control",
        PolicyDocument=_policy({"Effect": "Allow", "Action": "iam:GetUser", "Resource": user_arn}),
    )
    iam.put_user_policy(
        UserName=user, PolicyName="tls",
        PolicyDocument=_policy({
            "Effect": "Allow", "Action": "iam:ListUserTags", "Resource": user_arn,
            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
        }),
    )
    key = iam.create_access_key(UserName=user)["AccessKey"]
    as_user = _client_as(ctx, key["AccessKeyId"], key["SecretAccessKey"])
    act = ["iam:ListUserTags"]
    assert as_user.meta.endpoint_url.startswith("https://"), (
        f"the real call must travel over TLS for this check to mean anything; endpoint is "
        f"{as_user.meta.endpoint_url!r}"
    )

    _sim_settle(iam, user_arn, act, [user_arn], {"iam:ListUserTags": "allowed"},
                description="simulator, plaintext context, Allow-if-plaintext",
                ContextEntries=_tls_ctx("false"))
    tls_sim = _decisions(iam, user_arn, act, [user_arn],
                         ContextEntries=_tls_ctx("true"))["iam:ListUserTags"]["EvalDecision"]
    assert tls_sim == "implicitDeny", f"TLS context under Allow-if-plaintext: {tls_sim!r}"

    _settle(lambda: _outcome(lambda: as_user.get_user(UserName=user)), "OK",
            description="real GetUser positive control")
    denied, denied_message = _refusal(lambda: as_user.list_user_tags(UserName=user))
    assert denied == "AccessDenied", (
        f"a TLS request cannot satisfy aws:SecureTransport=false, so it must be refused with exactly "
        f"AccessDenied; got {denied!r}"
    )
    expected_message = _with_authorization_details(
        f"User: {user_arn} is not authorized to perform: iam:ListUserTags on resource: user "
        f"{user} because no identity-based policy allows the iam:ListUserTags action",
        denied_message,
    )
    assert denied_message == expected_message, (
        f"expected message {expected_message!r}, got {denied_message!r}"
    )
    assert (tls_sim == "allowed") == (denied == "OK"), (
        f"simulator for a TLS context said {tls_sim!r} but the real TLS call returned {denied!r}"
    )

    # --- Customary shape: Allow unconditionally, Deny when not over TLS.
    iam.put_user_policy(
        UserName=user, PolicyName="tls",
        PolicyDocument=_policy(
            {"Effect": "Allow", "Action": "iam:ListUserTags", "Resource": user_arn},
            {"Effect": "Deny", "Action": "iam:ListUserTags", "Resource": user_arn,
             "Condition": {"Bool": {"aws:SecureTransport": "false"}}},
        ),
    )
    _sim_settle(iam, user_arn, act, [user_arn], {"iam:ListUserTags": "allowed"},
                description="simulator, TLS context, Deny-if-plaintext",
                ContextEntries=_tls_ctx("true"))
    plain_sim = _decisions(iam, user_arn, act, [user_arn],
                           ContextEntries=_tls_ctx("false"))["iam:ListUserTags"]["EvalDecision"]
    assert plain_sim == "explicitDeny", f"plaintext context under Deny-if-plaintext: {plain_sim!r}"
    _settle(lambda: _outcome(lambda: as_user.list_user_tags(UserName=user)), "OK",
            description="real TLS ListUserTags under Allow + Deny-if-plaintext")

    # --- Restore the plaintext-only Allow: this denial follows a proven-effective grant on the same
    # action, so it can only be the condition -- not a policy that had not propagated yet.
    iam.put_user_policy(
        UserName=user, PolicyName="tls",
        PolicyDocument=_policy({
            "Effect": "Allow", "Action": "iam:ListUserTags", "Resource": user_arn,
            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
        }),
    )
    _settle(lambda: _outcome(lambda: as_user.list_user_tags(UserName=user)), "AccessDenied",
            description="real TLS ListUserTags once only a plaintext Allow remains")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
