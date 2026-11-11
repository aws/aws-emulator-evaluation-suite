"""iam-eval-deep-iam-1-date-greater-than-past-instant-allows."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "iam-eval-deep-iam-1-date-greater-than-past-instant-allows"
GROUP = 'policy_condition_time'
SERVICES = ['iam']

_POLICY = "sim2real-behav-time-after"
_PAST = "2020-01-01T00:00:00Z"
_FUTURE = "2099-01-01T00:00:00Z"
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


# The AccessDenied message ends in a per-call authorization id (also embedded in the console
# URL), so the full string is never repeatable: the message varies per call in that one token,
# and a full match pins every other character.
_AUTHZ_TAIL = (
    r"\. Go to https://\S+ for complete details, or call the GetRequestAuthorizationDetails "
    r"API with the following authorization id: [A-Za-z0-9]+"
)


def _expected_denial(message, head):
    """``head`` followed by the authorization-details pointer that ends ``message``: the pointer's
    region and per-request authorization id are the only parts read back from it."""
    found = re.search(_AUTHZ_TAIL + r"\Z", message or "")
    return head + (found.group(0) if found else ". Go to <authorization-details pointer>")


@tags("axis:happy-path", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """A DateGreaterThan aws:CurrentTime grant on a past instant allows the call, while the same
    document's DateGreaterThan grant on a future instant fails with AccessDenied and the exact
    message for the same principal, so the date condition is evaluated rather than ignored."""
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    user = ctx.unique_name("sim2real-behav-after-")
    iam.create_user(UserName=user, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user))
    user_arn = f"arn:aws:iam::{account}:user/{user}"

    iam.put_user_policy(UserName=user, PolicyName=_POLICY, PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "PastInstant", "Effect": "Allow", "Action": "iam:GetUser",
             "Resource": user_arn,
             "Condition": {"DateGreaterThan": {"aws:CurrentTime": _PAST}}},
            {"Sid": "FutureInstant", "Effect": "Allow", "Action": "iam:ListUserTags",
             "Resource": user_arn,
             "Condition": {"DateGreaterThan": {"aws:CurrentTime": _FUTURE}}},
            {"Sid": "Barrier", "Effect": "Allow", "Action": "iam:ListAccessKeys",
             "Resource": user_arn},
        ],
    }))
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user, PolicyName=_POLICY))

    key = iam.create_access_key(UserName=user)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user, AccessKeyId=key["AccessKeyId"]))
    me = ctx.client("iam", creds={"aws_access_key_id": key["AccessKeyId"],
                                  "aws_secret_access_key": key["SecretAccessKey"]})

    # Barrier on the unconditioned statement of the SAME document, three times running.
    streak = {"n": 0}

    def warm():
        streak["n"] = streak["n"] + 1 if _outcome(
            lambda: me.list_access_keys(UserName=user)) == ("OK", None) else 0
        return streak["n"]

    _poll(warm, lambda n: n >= 3, timeout_s=120, interval_s=2,
          description="the minted user's policy document becomes effective")

    for i in range(3):
        got = _outcome(lambda: me.get_user(UserName=user))
        assert got == ("OK", None), (
            f"call {i + 1}/3: DateGreaterThan {_PAST} is already true, so iam:GetUser must be "
            f"allowed; got {got!r}"
        )
    seen = me.get_user(UserName=user)["User"]
    assert seen["UserName"] == user and seen["Arn"] == user_arn, (
        f"the allowed GetUser must describe the minted user itself; got {seen!r}"
    )

    code, message = _outcome(lambda: me.list_user_tags(UserName=user))
    assert code == "AccessDenied", (
        f"DateGreaterThan {_FUTURE} is not yet true, so iam:ListUserTags must be AccessDenied; "
        f"got {(code, message)!r}"
    )
    expected = (
        f"User: {user_arn} is not authorized to perform: iam:ListUserTags on resource: user "
        f"{user} because no identity-based policy allows the iam:ListUserTags action"
    )
    assert message == _expected_denial(message, expected), (
        f"the future-instant denial must read as no applicable allow, exactly {expected!r} plus "
        f"the authorization-details pointer; got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
