"""action-wildcard-prefix-match-enforced-on-a-real-signed-call."""
from __future__ import annotations

import json
import time
import urllib.parse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "action-wildcard-prefix-match-enforced-on-a-real-signed-call"
GROUP = "policy_simulation"
SERVICES = ["iam"]

_POLICY_NAME = "sim2real-behav-action-wildcard"
_MARK = [{"Key": "sim2real", "Value": CHECK}]


def _budget_s(ctx, cap_s):
    """A poll's timeout, bounded by the runner's remaining time so the poll fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An Action wildcard is matched as a PREFIX on a real signed call: `iam:Get*` on one user ARN
    permits two different Get operations, refuses a List operation on the same resource with
    AccessDenied, and widening the statement to `iam:*` makes that call succeed."""
    iam = ctx.client("iam")

    user = ctx.unique_name("sim2real-awild-user-")
    iam.create_user(UserName=user, Path="/", Tags=_MARK)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user))
    user_arn = iam.get_user(UserName=user)["User"]["Arn"]

    _put(iam, user, ["iam:Get*", "iam:ListUserTags"], user_arn)
    ctx.on_cleanup(lambda: _drop_user_policy(iam, user, _POLICY_NAME))

    key = iam.create_access_key(UserName=user)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user, AccessKeyId=key["AccessKeyId"]))
    as_user = _signing_as(ctx, "iam", key)

    # --- Control: an action named in full, so credential and grant propagation is established
    #     without depending on any wildcard behaviour.
    ready = _poll(
        lambda: _outcome(lambda: as_user.list_user_tags(UserName=user)),
        lambda o: o == "OK",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the fully-named iam:ListUserTags grant becomes effective for the minted key",
    )
    assert ready == "OK", (
        f"the fully-named grant must work before any wildcard conclusion is drawn, or a refusal "
        f"below would mean nothing; expected 'OK', got {ready!r}"
    )

    # --- Positive control A: iam:GetUser is inside the prefix.
    inside = _poll(
        lambda: _outcome(lambda: as_user.get_user(UserName=user)),
        lambda o: o == "OK",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="iam:Get* permits the real signed iam:GetUser",
    )
    assert inside == "OK", (
        f"iam:GetUser is inside the iam:Get* prefix, so the real signed call must succeed; expected "
        f"'OK', got {inside!r} -- an emulator that string-compares the Action element denies this"
    )

    # --- Positive control B: a SECOND, unrelated Get action, whose authorized-but-absent answer is
    #     NoSuchEntity. This is what separates "the prefix matched" from "GetUser was special-cased":
    #     an unauthorized caller would get AccessDenied here instead.
    absent, absent_msg = _rejected(lambda: as_user.get_login_profile(UserName=user))
    assert absent == "NoSuchEntity", (
        f"the user has no login profile, so an AUTHORIZED iam:GetLoginProfile must report exactly "
        f"NoSuchEntity -- the resource is missing, not the permission; got {absent!r}, and "
        f"AccessDenied there would mean iam:Get* matched only the one action the check happened to "
        f"try first"
    )
    assert absent_msg == f"Login Profile for User {user} cannot be found.", (
        f"authorized GetLoginProfile on a user with no login profile message: {absent_msg!r}"
    )

    # --- Break exactly one thing: the action's PREFIX. Same signer, same resource, same instant,
    #     same document.
    # message varies: IAM appends a per-request authorization id (and a console URL
    # carrying it) to this denial, so the code is asserted exactly and the message by the
    # stable part that names the refused action.
    outside, outside_msg = _rejected(lambda: as_user.list_access_keys(UserName=user))
    assert "is not authorized to perform: iam:ListAccessKeys" in (outside_msg or ""), (
        f"the denial must name the refused action iam:ListAccessKeys; got {outside_msg!r}"
    )
    assert outside == "AccessDenied", (
        f"iam:ListAccessKeys is outside the iam:Get* prefix, so the identical real signed call "
        f"against the same resource must be refused with exactly AccessDenied; got {outside!r} -- an "
        f"emulator whose matcher reads any '*' as match-all over-permits here"
    )

    # --- Restore: widen the wildcard and the refused call must work, proving the refusal came from
    #     the prefix and not from a blanket denial of that operation.
    _put(iam, user, ["iam:*"], user_arn)
    widened = _poll(
        lambda: _outcome(lambda: as_user.list_access_keys(UserName=user)),
        lambda o: o == "OK",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="widening the Action element to iam:* permits the previously refused call",
    )
    assert widened == "OK", (
        f"with the statement widened to iam:*, the identical real signed iam:ListAccessKeys must "
        f"succeed -- so the earlier refusal was the prefix's doing; expected 'OK', got {widened!r}"
    )

    # --- Narrow it back: the refusal must return, so the widening was not a one-way latch.
    _put(iam, user, ["iam:Get*", "iam:ListUserTags"], user_arn)
    narrowed = _poll(
        lambda: _outcome(lambda: as_user.list_access_keys(UserName=user)),
        lambda o: o == "AccessDenied",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="narrowing the Action element back to iam:Get* restores the refusal",
    )
    assert narrowed == "AccessDenied", (
        f"restoring the iam:Get* prefix must restore the refusal with exactly AccessDenied; got "
        f"{narrowed!r} -- an emulator that only ever WIDENS effective permissions fails here"
    )
    # ... and the in-prefix action is untouched by the narrowing.
    still_inside = _outcome(lambda: as_user.get_user(UserName=user))
    assert still_inside == "OK", (
        f"narrowing the wildcard must leave the in-prefix action working, so the change was a "
        f"narrowing and not a revoke; expected 'OK', got {still_inside!r}"
    )


# ===== helpers =====
def _outcome(fn):
    """``"OK"`` on success, else the AWS error code.

    ``"OK"`` is a truthy sentinel no AWS error code can equal, and every caller either feeds it to
    ``_poll`` (which RAISES on timeout, so a target that never converges cannot pass) or asserts it
    against an exact expected value. Refusals asserted WITHOUT a preceding poll go through
    ``_rejected``, which raises on an unexpected success.
    """
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code") or "NO_ERROR_CODE"
    return "OK"


def _rejected(fn):
    """(Error.Code, Error.Message) of a call real AWS MUST refuse; an unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code") or "NO_ERROR_CODE", err.get("Message")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    """Bounded retry with a deadline. RAISES on timeout -- never returns its last value on failure."""
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} did not happen within {timeout_s}s; last observation {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


def _signing_as(ctx, service, key):
    """A client for ``service`` signing as the principal that owns ``key``.

    ``ctx.client(..., creds=...)`` is the engine's re-signing idiom: it keeps THIS target's
    endpoint, region and TLS settings, so the second hop can never reach real AWS by accident.
    """
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": key["AccessKeyId"],
            "aws_secret_access_key": key["SecretAccessKey"],
        },
    )


def _put(iam, user, actions, resource):
    """Rewrite the ONE inline policy under test, then read the stored document back.

    The read-back goes through GetUserPolicy -- a different operation than the write -- so a target
    that silently keeps the previous document cannot make the next authorization leg look like a
    matcher bug.
    """
    document = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": actions, "Resource": resource}],
    }
    iam.put_user_policy(
        UserName=user, PolicyName=_POLICY_NAME, PolicyDocument=json.dumps(document)
    )
    stored = iam.get_user_policy(UserName=user, PolicyName=_POLICY_NAME)["PolicyDocument"]
    if isinstance(stored, str):
        stored = json.loads(urllib.parse.unquote(stored))
    stored_actions = stored["Statement"][0]["Action"]
    if isinstance(stored_actions, str):
        stored_actions = [stored_actions]
    assert stored_actions == list(actions), (
        f"the inline policy's Action element must be exactly what was just written before its "
        f"enforcement is probed: expected {list(actions)!r}, GetUserPolicy returned "
        f"{stored_actions!r}"
    )


def _drop_user_policy(iam, user, policy_name):
    """Teardown-only: tolerate the inline policy already being absent. Scoped to this one name."""
    try:
        iam.delete_user_policy(UserName=user, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
