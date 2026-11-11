"""simulate-allow-agrees-with-a-real-signed-call."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "simulate-allow-agrees-with-a-real-signed-call"
GROUP = 'policy_simulation'
SERVICES = ['iam']


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


def _client_for_credentials(ctx, access_key_id, secret_access_key, service="iam"):
    """A client signing AS the minted principal."""
    return ctx.client(service, creds={
        "aws_access_key_id": access_key_id,
        "aws_secret_access_key": secret_access_key,
    })


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


def _decisions(iam, source_arn, actions, resource_arns):
    results = iam.simulate_principal_policy(
        PolicySourceArn=source_arn, ActionNames=actions, ResourceArns=resource_arns
    )["EvaluationResults"]
    return {r["EvalActionName"]: r for r in results}


def _denial_message(fn):
    """Error.Message of a call real AWS refuses; an unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Message") or ""
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c7")
def run(ctx) -> None:
    """SimulatePrincipalPolicy agrees with enforcement: iam:GetUser simulated 'allowed' succeeds when
    the user signs it, iam:ListAccessKeys simulated 'implicitDeny' fails with AccessDenied and its
    exact message, and after a grant it simulates 'allowed'."""
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-behav-agree-user-")
    policy_name = "sim2real-behav-agree-getuser-only"

    iam.create_user(UserName=user, Path="/")
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user))
    user_arn = iam.get_user(UserName=user)["User"]["Arn"]

    # Exactly iam:GetUser on this user's own ARN. iam:ListAccessKeys is deliberately absent, so it
    # is denied by ABSENCE (implicitDeny) rather than by a Deny statement.
    iam.put_user_policy(
        UserName=user,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "iam:GetUser", "Resource": user_arn},
            ],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user, PolicyName=policy_name))

    key = iam.create_access_key(UserName=user)["AccessKey"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(UserName=user, AccessKeyId=key["AccessKeyId"])
    )
    as_user = _client_for_credentials(ctx, key["AccessKeyId"], key["SecretAccessKey"])

    # --- Axis A: what the simulator says. Attachment is eventually consistent, so poll the allow.
    actions = ["iam:GetUser", "iam:ListAccessKeys"]
    sim = _poll(
        lambda: _decisions(iam, user_arn, actions, [user_arn]),
        lambda d: d.get("iam:GetUser", {}).get("EvalDecision") == "allowed",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the simulator reports iam:GetUser allowed for the new inline policy",
    )
    assert sim["iam:GetUser"]["EvalDecision"] == "allowed", (
        "the inline policy grants iam:GetUser on this exact ARN, so the simulator must say "
        f"'allowed'; got {sim['iam:GetUser']['EvalDecision']!r}"
    )
    assert sim["iam:ListAccessKeys"]["EvalDecision"] == "implicitDeny", (
        "iam:ListAccessKeys appears in no statement, so the simulator must say 'implicitDeny' -- "
        f"not 'explicitDeny' and not 'allowed'; got {sim['iam:ListAccessKeys']['EvalDecision']!r}"
    )
    matched = sim["iam:ListAccessKeys"].get("MatchedStatements", [])
    assert matched == [], (
        "an implicit deny is a deny by ABSENCE, so no statement may be reported as matched; got "
        f"{matched!r}"
    )

    # --- Axis B: what the enforcement path does. IAM replicates both the key and the grant
    # per-replica and exposes NO api that reports either as effective, so the wait is a bounded poll
    # on the granted call itself; it raises rather than skipping if it never converges.
    # Polling only past the credential codes and asserting success in one shot flakes, because a
    # replica that has the key can still be missing the policy.
    got = _poll(
        lambda: _try_get_user(as_user, user),
        lambda r: r[0] == "OK",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the granted iam:GetUser becomes effective for the minted key on a real call",
    )
    assert got[0] == "OK", (
        "the simulator said iam:GetUser is allowed, so the real signed call by this principal must "
        f"succeed; it returned {got[0]!r}"
    )
    assert got[1] == user_arn, (
        f"the real call must have been made AS the new user: expected {user_arn!r}, got "
        f"{got[1]!r} -- a different ARN means the harness's own identity leaked through"
    )

    denied = _error_code(lambda: as_user.list_access_keys(UserName=user))
    assert denied == "AccessDenied", (
        "the simulator said iam:ListAccessKeys is implicitDeny, so the real signed call must be "
        f"refused with exactly AccessDenied; got {denied!r}"
    )
    denied_msg = _denial_message(lambda: as_user.list_access_keys(UserName=user))
    expected_msg = _with_authorization_details(
        f"User: {user_arn} is not authorized to perform: iam:ListAccessKeys on resource: user "
        f"{user} because no identity-based policy allows the iam:ListAccessKeys action",
        denied_msg,
    )
    assert denied_msg == expected_msg, f"expected message {expected_msg!r}, got {denied_msg!r}"

    # --- The relation itself: one equality over both views, so a disagreement names the action.
    simulated = {a: sim[a]["EvalDecision"] == "allowed" for a in actions}
    enforced = {"iam:GetUser": got[0] == "OK", "iam:ListAccessKeys": denied != "AccessDenied"}
    assert simulated == enforced, (
        "SimulatePrincipalPolicy and the enforcement path disagree for this principal: simulator "
        f"said {simulated!r}, the real signed calls behaved as {enforced!r}"
    )

    # --- Restore beat: this implicitDeny is a denial BY ABSENCE, not a Deny statement, so its
    # negative has no "break" step to undo -- but it does have a state to change. Granting the
    # missing action must flip BOTH views together; if it did not, the earlier denial could have
    # been caused by something other than the missing grant (a typo'd ARN, a stuck replica, an
    # unrelated restriction), and the check would never have told the difference.
    iam.put_user_policy(
        UserName=user,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["iam:GetUser", "iam:ListAccessKeys"],
                    "Resource": user_arn,
                },
            ],
        }),
    )
    granted = _poll(
        lambda: _decisions(iam, user_arn, actions, [user_arn]),
        lambda d: d.get("iam:ListAccessKeys", {}).get("EvalDecision") == "allowed",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the simulator reports iam:ListAccessKeys allowed once the grant is added",
    )
    assert granted["iam:ListAccessKeys"]["EvalDecision"] == "allowed", (
        "adding iam:ListAccessKeys to the same policy must flip the simulator's verdict from "
        f"implicitDeny to allowed; got {granted['iam:ListAccessKeys']['EvalDecision']!r}"
    )
    restored = _poll(
        lambda: _error_code(lambda: as_user.list_access_keys(UserName=user)),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the newly-granted iam:ListAccessKeys becomes effective on a real signed call",
    )
    assert restored == "UNEXPECTED_SUCCESS", (
        "the simulator now says iam:ListAccessKeys is allowed, so the identical real signed call "
        f"that was just refused must now succeed; got {restored!r}"
    )


def _try_get_user(client, user_name):
    """(code_or_OK, arn_or_None) for a real signed GetUser -- one probe, two observations."""
    try:
        return "OK", client.get_user(UserName=user_name)["User"]["Arn"]
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
