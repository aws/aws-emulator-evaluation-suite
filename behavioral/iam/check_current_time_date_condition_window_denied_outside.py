"""current-time-date-condition-window-denied-outside."""
from __future__ import annotations

import datetime as dt
import json
import time

from behavioral_harness import tags

CHECK = "current-time-date-condition-window-denied-outside"
GROUP = "policy-evaluation"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Real signed calls under aws:CurrentTime conditions one day from now follow the server clock:
    DateGreaterThan(tomorrow) and DateLessThan(yesterday) are denied with AccessDenied, the opposite bounds
    and a [yesterday, tomorrow] Equals window are allowed, and that window moved into the future is denied."""
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-datewin-")
    now = dt.datetime.now(dt.timezone.utc)
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    yesterday = (now - dt.timedelta(days=1)).strftime(fmt)
    tomorrow = (now + dt.timedelta(days=1)).strftime(fmt)
    later = (now + dt.timedelta(days=2)).strftime(fmt)

    user_arn = iam.create_user(UserName=user)["User"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user))
    key = iam.create_access_key(UserName=user)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user, AccessKeyId=key["AccessKeyId"]))

    t = "aws:CurrentTime"
    statements = [
        {"Sid": "Control", "Effect": "Allow", "Action": "iam:GetUser", "Resource": user_arn},
        {"Sid": "AfterTomorrow", "Effect": "Allow", "Action": "iam:ListAccountAliases",
         "Resource": "*", "Condition": {"DateGreaterThan": {t: tomorrow}}},
        {"Sid": "BeforeTomorrow", "Effect": "Allow", "Action": "iam:GetAccountSummary",
         "Resource": "*", "Condition": {"DateLessThan": {t: tomorrow}}},
        {"Sid": "AfterYesterday", "Effect": "Allow", "Action": "iam:ListGroups",
         "Resource": "*", "Condition": {"DateGreaterThan": {t: yesterday}}},
        {"Sid": "BeforeYesterday", "Effect": "Allow", "Action": "iam:ListRoles",
         "Resource": "*", "Condition": {"DateLessThan": {t: yesterday}}},
        {"Sid": "WindowNow", "Effect": "Allow", "Action": "iam:ListInstanceProfiles",
         "Resource": "*", "Condition": {"DateGreaterThanEquals": {t: yesterday},
                                        "DateLessThanEquals": {t: tomorrow}}},
        {"Sid": "WindowFuture", "Effect": "Allow", "Action": "iam:ListServerCertificates",
         "Resource": "*", "Condition": {"DateGreaterThanEquals": {t: tomorrow},
                                        "DateLessThanEquals": {t: later}}},
    ]
    iam.put_user_policy(UserName=user, PolicyName="window", PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": statements}))
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user, PolicyName="window"))

    me = ctx.client("iam", creds={"aws_access_key_id": key["AccessKeyId"],
                                  "aws_secret_access_key": key["SecretAccessKey"]})
    got = _until_allowed(lambda: me.get_user(UserName=user), timeout_s=120)
    assert got["User"]["Arn"] == user_arn, f"control GetUser returned {got['User']['Arn']!r}"

    allowed = {
        "DateLessThan(tomorrow)": lambda: me.get_account_summary(),
        "DateGreaterThan(yesterday)": lambda: me.list_groups(MaxItems=1),
        "window [yesterday, tomorrow]": lambda: me.list_instance_profiles(MaxItems=1),
    }
    for label, fn in allowed.items():
        _until_allowed(fn, timeout_s=60, label=label)

    acct = ctx.account
    denied = {
        # > tomorrow. message varies: this denial ends with a per-request authorization id, so
        # the code and the named action are graded.
        "iam:ListAccountAliases": (lambda: me.list_account_aliases(), None),
        # < yesterday
        "iam:ListRoles": (lambda: me.list_roles(MaxItems=1), f"arn:aws:iam::{acct}:role/"),
        # future window
        "iam:ListServerCertificates": (
            lambda: me.list_server_certificates(MaxItems=1),
            f"arn:aws:iam::{acct}:server-certificate/",
        ),
    }
    for action, (fn, resource) in denied.items():
        expected = None
        if resource is not None:
            expected = (
                f"User: {user_arn} is not authorized to perform: {action} on resource: {resource} "
                f"because no identity-based policy allows the {action} action"
            )
        _assert_stably_denied(fn, action, expected)

    for label, fn in allowed.items():
        _until_allowed(fn, timeout_s=30, label=label)


def _until_allowed(fn, timeout_s, label="control"):
    """Retry only on the two propagation codes a brand-new key/policy produces."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            last = e.response["Error"]["Code"]
            if last not in ("InvalidClientTokenId", "AccessDenied"):
                raise
        time.sleep(3)
    raise AssertionError(f"{label}: expected ALLOWED, still {last!r} after {timeout_s}s")


def _denied_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message") or ""
    return "<allowed>", ""


def _assert_stably_denied(fn, action, expected, rounds=3):
    for i in range(rounds):
        code, msg = _denied_code(fn)
        assert code == "AccessDenied", (
            f"{action}: expected AccessDenied (round {i + 1}/{rounds}), got {code!r} {msg!r}"
        )
        if expected is not None:
            assert msg == expected, f"{action}: expected message {expected!r}, got {msg!r}"
        else:
            # message varies: per-request authorization id; the named action is its stable part
            assert f"perform: {action}" in msg, f"{action}: denial message names another action: {msg!r}"
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
