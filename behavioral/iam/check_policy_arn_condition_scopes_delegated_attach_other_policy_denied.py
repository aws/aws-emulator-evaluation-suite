"""policy-arn-condition-scopes-delegated-attach-other-policy-denied."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "policy-arn-condition-scopes-delegated-attach-other-policy-denied"
GROUP = "policy-evaluation"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An iam:PolicyARN condition limits a delegate to one managed policy: it attaches and detaches
    the allowed policy, while attaching another, or detaching that other once an administrator
    attached it, fails with AccessDenied and the exact message and leaves the attachments unchanged."""
    iam = ctx.client("iam")
    base = ctx.unique_name("sim2real-polarn-")
    path = f"/{base}/"
    target = f"{base}-target"
    delegate = f"{base}-delegate"

    iam.create_user(UserName=target)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=target))
    harmless = json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Action": "iam:GetUser",
        "Resource": f"arn:aws:iam::*:user{path}nobody"}]})
    p_ok = iam.create_policy(PolicyName=f"{base}-ok", Path=path, PolicyDocument=harmless)[
        "Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=p_ok))
    p_other = iam.create_policy(PolicyName=f"{base}-other", Path=path, PolicyDocument=harmless)[
        "Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=p_other))
    # Registered after both policies so LIFO detaches before the policy deletes run.
    ctx.on_cleanup(lambda: _detach_all(iam, target, (p_ok, p_other)))

    target_arn = iam.get_user(UserName=target)["User"]["Arn"]
    delegate_arn = iam.create_user(UserName=delegate)["User"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=delegate))
    key = iam.create_access_key(UserName=delegate)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=delegate, AccessKeyId=key["AccessKeyId"]))
    iam.put_user_policy(UserName=delegate, PolicyName="delegated", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "Control", "Effect": "Allow", "Action": "iam:GetUser",
             "Resource": delegate_arn},
            {"Sid": "OnlyThisPolicy", "Effect": "Allow",
             "Action": ["iam:AttachUserPolicy", "iam:DetachUserPolicy"],
             "Resource": target_arn,
             "Condition": {"ArnEquals": {"iam:PolicyARN": p_ok}}},
        ]}))
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=delegate, PolicyName="delegated"))

    me = ctx.client("iam", creds={"aws_access_key_id": key["AccessKeyId"],
                                  "aws_secret_access_key": key["SecretAccessKey"]})
    got = _until_allowed(lambda: me.get_user(UserName=delegate), timeout_s=120)
    assert got["User"]["Arn"] == delegate_arn, f"control GetUser returned {got['User']['Arn']!r}"

    # Allowed: the condition's policy, attach then detach.
    _until_allowed(lambda: me.attach_user_policy(UserName=target, PolicyArn=p_ok),
                   timeout_s=60, label="attach the allowed policy")
    assert _attached(iam, target) == [p_ok], (
        f"after the delegate's allowed attach, target has {_attached(iam, target)!r}"
    )

    # Denied: any other policy ARN, and nothing is attached.
    _assert_stably_denied(lambda: me.attach_user_policy(UserName=target, PolicyArn=p_other),
                          "iam:AttachUserPolicy", delegate_arn, target)
    assert _attached(iam, target) == [p_ok], (
        f"a denied attach changed the target's policies to {_attached(iam, target)!r}"
    )

    _until_allowed(lambda: me.detach_user_policy(UserName=target, PolicyArn=p_ok),
                   timeout_s=60, label="detach the allowed policy")
    assert _attached(iam, target) == [], (
        f"after the delegate's allowed detach, target still has {_attached(iam, target)!r}"
    )

    # The condition also gates DETACH: an admin-attached other policy cannot be removed.
    iam.attach_user_policy(UserName=target, PolicyArn=p_other)
    _assert_stably_denied(lambda: me.detach_user_policy(UserName=target, PolicyArn=p_other),
                          "iam:DetachUserPolicy", delegate_arn, target)
    assert _attached(iam, target) == [p_other], (
        f"a denied detach changed the target's policies to {_attached(iam, target)!r}"
    )


def _attached(iam, user):
    arns = []
    for page in iam.get_paginator("list_attached_user_policies").paginate(UserName=user):
        arns.extend(p["PolicyArn"] for p in page["AttachedPolicies"])
    return sorted(arns)


def _detach_all(iam, user, arns):
    _leaks: list = []
    from botocore.exceptions import ClientError

    for arn in arns:
        try:
            iam.detach_user_policy(UserName=user, PolicyArn=arn)
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                _leaks.append((f"detach {arn} from {user}: {e}", e))
    if _leaks:
        raise RuntimeError("; ".join(m for m, _ in _leaks)) from next(
            (e for _, e in _leaks if e is not None), None
        )


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
    """(code, message) of a call real AWS refuses; an unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected AccessDenied, but the call SUCCEEDED and returned {result!r}")


def _assert_stably_denied(fn, action, caller_arn, target_user, rounds=3):
    expected = (
        f"User: {caller_arn} is not authorized to perform: {action} on resource: user {target_user} "
        f"because no identity-based policy allows the {action} action"
    )
    for i in range(rounds):
        code, msg = _denied_code(fn)
        assert code == "AccessDenied", (
            f"{action}: expected AccessDenied (round {i + 1}/{rounds}), got {code!r} {msg!r}"
        )
        assert msg == expected, f"{action}: expected message {expected!r}, got {msg!r}"
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
