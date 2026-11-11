"""iam-eval-deep-iam-1-date-less-than-deadline-passes-then-denied."""
from __future__ import annotations

import datetime as dt
import email.utils
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "iam-eval-deep-iam-1-date-less-than-deadline-passes-then-denied"
GROUP = 'policy_condition_time_denied'
SERVICES = ['iam']

_BASE = "sim2real-behav-time-base"
_TIMED = "sim2real-behav-time-deadline"
_WINDOW_S = 120
_PROPAGATION = frozenset({"InvalidClientTokenId", "SignatureDoesNotMatch"})


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


def _poll(probe, predicate, *, timeout_s, interval_s, description, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{description}: the run budget ended first; not graded")
            raise AssertionError(
                f"{description} not reached within {timeout_s}s; last observation {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


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


def _iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


# timing:real-time — ttl: 120 s https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c1", "timing:real-time")
def run(ctx) -> None:
    """A DateLessThan aws:CurrentTime grant set to server time + 120 s is honoured before the
    deadline and AccessDenied after it (measured elapsed >= 120 s), on the same principal and action,
    while an unconditioned grant on the same principal keeps working.

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
    """
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    user = ctx.unique_name("sim2real-behav-time-")
    iam.create_user(UserName=user, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user))
    user_arn = f"arn:aws:iam::{account}:user/{user}"

    iam.put_user_policy(UserName=user, PolicyName=_BASE, PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "iam:GetUser", "Resource": user_arn}],
    }))
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user, PolicyName=_BASE))

    key = iam.create_access_key(UserName=user)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user, AccessKeyId=key["AccessKeyId"]))
    me = ctx.client("iam", creds={"aws_access_key_id": key["AccessKeyId"],
                                  "aws_secret_access_key": key["SecretAccessKey"]})

    # Warm-up on the UNCONDITIONED grant: the key and base policy are live, three times running.
    streak = {"n": 0}

    def warm():
        streak["n"] = streak["n"] + 1 if _outcome(
            lambda: me.get_user(UserName=user)) == ("OK", None) else 0
        return streak["n"]

    _poll(warm, lambda n: n >= 3, timeout_s=_budget_s(ctx, 120), interval_s=1,
          description="the minted user's unconditioned iam:GetUser grant becomes effective", ctx=ctx)

    # The deadline is anchored to the server's Date header rounded UP a second, with the monotonic
    # clock started before the request is sent, so elapsed time at denial is a lower bound.
    t_start = time.monotonic()
    resp = me.get_user(UserName=user)
    date_hdr = resp["ResponseMetadata"]["HTTPHeaders"].get("date")
    assert date_hdr, (
        f"the response must carry a Date header; metadata was {resp['ResponseMetadata']!r}"
    )
    server_now = email.utils.parsedate_to_datetime(date_hdr).astimezone(dt.timezone.utc)
    created_at = server_now.replace(microsecond=0) + dt.timedelta(seconds=1)
    deadline = created_at + dt.timedelta(seconds=_WINDOW_S)
    iam.put_user_policy(UserName=user, PolicyName=_TIMED, PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "iam:ListUserTags", "Resource": user_arn,
                       "Condition": {"DateLessThan": {"aws:CurrentTime": _iso(deadline)}}}],
    }))
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user, PolicyName=_TIMED))

    def timed():
        return _outcome(lambda: me.list_user_tags(UserName=user))

    def elapsed():
        return time.monotonic() - t_start

    # The new grant propagates per replica: a first success can be followed by a stale replica's
    # AccessDenied, so poll (well inside the window) for three consecutive successes.
    successes = []

    def three_in_a_row():
        got = timed()
        if got == ("OK", None):
            successes.append(round(elapsed(), 1))
        else:
            successes.clear()
        return len(successes)

    _poll(three_in_a_row, lambda n: n >= 3, timeout_s=_budget_s(ctx, _WINDOW_S), interval_s=1,
          description=f"three consecutive successes under DateLessThan {_iso(deadline)}", ctx=ctx)
    assert len(successes) == 3, f"expected exactly three consecutive successes; got {successes!r}"
    assert successes[-1] < _WINDOW_S, (
        f"the three successes must all land inside the {_WINDOW_S}s window; elapsed {successes!r}"
    )

    # Now wait for the deadline for real: the identical call, unchanged, until it is refused.
    denied = _poll(timed, lambda o: o[0] != "OK", timeout_s=_budget_s(ctx, _WINDOW_S + 60), interval_s=1,
                   description=f"the DateLessThan {_iso(deadline)} grant expiring", ctx=ctx)
    denied_at = elapsed()
    code, message = denied
    assert code == "AccessDenied", (
        f"once aws:CurrentTime passes the deadline the call must be AccessDenied; got {denied!r}"
    )
    no_allow = (
        f"User: {user_arn} is not authorized to perform: iam:ListUserTags on resource: user "
        f"{user} because no identity-based policy allows the iam:ListUserTags action"
    )
    expected = _with_authorization_details(no_allow, message)
    assert message == expected, f"the expired grant must read as no applicable allow; got {message!r}"
    assert denied_at >= _WINDOW_S, (
        f"the denial arrived at measured elapsed {denied_at:.1f}s, before the {_WINDOW_S}s "
        f"deadline {_iso(deadline)} (created {_iso(created_at)}, Date header {date_hdr!r})"
    )
    print(f"[{CHECK}] successes at {successes}s; AccessDenied at measured elapsed "
          f"{denied_at:.1f}s (deadline {_iso(deadline)})")

    # An expired deadline stays expired, and the denial is specific to the timed grant: the
    # unconditioned grant on the same principal is unaffected.
    again = timed()
    assert again[0] == "AccessDenied", f"a passed deadline must stay passed; got {again!r}"
    expected = _with_authorization_details(no_allow, again[1])
    assert again[1] == expected, f"expected message {expected!r}, got {again[1]!r}"
    control = _outcome(lambda: me.get_user(UserName=user))
    assert control == ("OK", None), (
        f"the unconditioned iam:GetUser grant must still work after the deadline; got {control!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
