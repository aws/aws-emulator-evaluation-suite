"""requested-region-for-global-iam-is-us-east-1-other-region-denied."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "requested-region-for-global-iam-is-us-east-1-other-region-denied"
GROUP = "policy-evaluation"
SERVICES = ["iam"]

# IAM is a GLOBAL service: its requests are authorized with aws:RequestedRegion = us-east-1
# whatever region the caller's client is configured for. The literal is the contract, not an
# account or deployment choice, so it is legitimate here.
_IAM_REGION = "us-east-1"
_OTHER_REGION = "eu-west-1"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """aws:RequestedRegion on a call to the global IAM endpoint is us-east-1 whatever region the
    client uses: statements for us-east-1 or StringNotEquals another region allow, while statements
    for another region or StringNotEquals us-east-1 fail with AccessDenied and the exact message."""
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-reqreg-")
    rr = "aws:RequestedRegion"

    user_arn = iam.create_user(UserName=user)["User"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user))
    key = iam.create_access_key(UserName=user)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user, AccessKeyId=key["AccessKeyId"]))

    statements = [
        {"Sid": "Control", "Effect": "Allow", "Action": "iam:GetUser", "Resource": user_arn},
        {"Sid": "IsIamRegion", "Effect": "Allow", "Action": "iam:GetAccountSummary",
         "Resource": "*", "Condition": {"StringEquals": {rr: _IAM_REGION}}},
        {"Sid": "NotOther", "Effect": "Allow", "Action": "iam:ListGroups",
         "Resource": "*", "Condition": {"StringNotEquals": {rr: _OTHER_REGION}}},
        {"Sid": "IsOther", "Effect": "Allow", "Action": "iam:ListAccountAliases",
         "Resource": "*", "Condition": {"StringEquals": {rr: _OTHER_REGION}}},
        {"Sid": "NotIamRegion", "Effect": "Allow", "Action": "iam:ListRoles",
         "Resource": "*", "Condition": {"StringNotEquals": {rr: _IAM_REGION}}},
    ]
    iam.put_user_policy(UserName=user, PolicyName="region", PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": statements}))
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user, PolicyName="region"))

    # Deliberately configured for the run's region: the decision must not follow it.
    me = ctx.client("iam", region=ctx.region,
                    creds={"aws_access_key_id": key["AccessKeyId"],
                           "aws_secret_access_key": key["SecretAccessKey"]})
    got = _until_allowed(lambda: me.get_user(UserName=user), timeout_s=120)
    assert got["User"]["Arn"] == user_arn, f"control GetUser returned {got['User']['Arn']!r}"

    allowed = {
        f"RequestedRegion == {_IAM_REGION}": lambda: me.get_account_summary(),
        f"RequestedRegion != {_OTHER_REGION}": lambda: me.list_groups(MaxItems=1),
    }
    for label, fn in allowed.items():
        _until_allowed(fn, timeout_s=60, label=label)

    account = user_arn.split(":")[4]
    denied = {   # action: (call, resource AWS names, authorization details appended)
        "iam:ListAccountAliases": (lambda: me.list_account_aliases(), "*", True),  # == other region
        "iam:ListRoles": (lambda: me.list_roles(MaxItems=1),                       # != us-east-1
                          f"arn:aws:iam::{account}:role/", False),
    }
    for action, (fn, resource, details) in denied.items():
        _assert_stably_denied(fn, action, user_arn, resource, details)

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


def _assert_stably_denied(fn, action, user_arn, resource, details, rounds=3):
    for i in range(rounds):
        code, msg = _denied_code(fn)
        assert code == "AccessDenied", (
            f"{action}: expected AccessDenied (round {i + 1}/{rounds}), got {code!r} {msg!r}"
        )
        want = _denial_message(user_arn, action, resource, "identity-based", msg, details=details)
        assert msg == want, f"{action}: AccessDenied message: expected {want!r}, got {msg!r}"
        time.sleep(2)

# IAM's console host for authorization details is fixed to its global partition region.
_DETAILS_URL = "https://us-east-1.console.aws.amazon.com/iam/home?region=us-east-1#/authorization-details/"


def _denial_message(principal_arn, action, resource, why, message, *, details):
    """The exact AccessDenied message AWS writes for this principal, action and resource.

    ``why`` is the policy type AWS names (``identity-based``, ``session``). With ``details``, AWS
    appends a per-request authorization id, read back from the message and placed twice.
    """
    base = (
        f"User: {principal_arn} is not authorized to perform: {action} on resource: {resource} "
        f"because no {why} policy allows the {action} action"
    )
    if not details:
        return base
    auth = (message or "").rsplit(" ", 1)[-1]
    return (
        f"{base}. Go to {_DETAILS_URL}{auth} for complete details, or call the "
        f"GetRequestAuthorizationDetails API with the following authorization id: {auth}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
