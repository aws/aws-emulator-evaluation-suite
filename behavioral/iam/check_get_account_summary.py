"""get-account-summary."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-account-summary"
GROUP = 'account_summary'
SERVICES = ['iam']


def _no_policy_denial(user_arn: str, action: str, message: str | None) -> str:
    """AWS's refusal of ``user_arn``, which no policy grants ``action``. It ends with a per-request
    authorization id, given twice (in a console URL and on its own), the only part read back from
    ``message``."""
    found = re.search(
        r"\. Go to https://[a-z0-9-]+\.console\.aws\.amazon\.com/iam/home\?region=[a-z0-9-]+"
        r"#/authorization-details/(\w+) for complete details, or call the GetRequestAuthorizationDetails "
        r"API with the following authorization id: \1\Z",
        message or "",
    )
    head = (
        f"User: {user_arn} is not authorized to perform: iam:{action} on resource: * "
        f"because no identity-based policy allows the iam:{action} action"
    )
    return head + (found.group(0) if found else ". Go to <authorization-details pointer>")


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. Raises if fn()
    succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _poll_until(ctx, fn, pred, timeout_s=30, interval_s=2):
    """Call fn() until pred(result) is truthy; raise on timeout rather than returning a stale
    result."""
    deadline = time.monotonic() + timeout_s
    result = fn()
    while not pred(result):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"condition not reached within {timeout_s}s; last observation {result!r}"
            )
        time.sleep(interval_s)
        result = fn()
    return result


def _unprivileged_client(ctx):
    """A brand-new IAM user with ZERO attached permissions + a minted access key, returned as (an
    IAM client authenticated as that user, its ARN). A fresh IAM principal implicit-denies
    everything, so any call through it is expected AccessDenied. Access-key propagation is not instant, so poll STS
    until the creds are recognized. Cleanup is registered."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("nopriv-")
    user_arn = iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])["User"]["Arn"]

    def _cleanup():
        try:
            for k in iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]:
                iam.delete_access_key(UserName=user_name, AccessKeyId=k["AccessKeyId"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_user(UserName=user_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    created = iam.create_access_key(UserName=user_name)["AccessKey"]
    creds = {
        "aws_access_key_id": created["AccessKeyId"],
        "aws_secret_access_key": created["SecretAccessKey"],
    }
    unpriv_sts = ctx.client("sts", creds=creds)
    # Bounded by the runner's remaining time, so a key that never authenticates fails here.
    budget_s = max(1.0, min(60.0, (ctx.time_left() or 60.0) - 5.0))
    deadline = time.monotonic() + budget_s
    while True:
        try:
            unpriv_sts.get_caller_identity()
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in (
                "InvalidClientTokenId",
                "InvalidAccessKeyId",
            ):
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"minted access key was not recognized within {budget_s:.0f}s") from exc
            time.sleep(3)
    return ctx.client("iam", creds=creds), user_arn


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetAccountSummary's SummaryMap.Users grows by exactly 1 when the check creates a user, and a
    zero-permission user's call fails with AccessDenied and the exact no-policy message."""
    iam = ctx.client("iam")
    before = iam.get_account_summary()["SummaryMap"]
    users_before = before.get("Users", 0)

    user_name = ctx.unique_name("sumuser-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    after = _poll_until(
        ctx,
        lambda: iam.get_account_summary()["SummaryMap"],
        lambda m: m.get("Users", 0) == users_before + 1,
        timeout_s=30,
        interval_s=2,
    )
    assert after.get("Users", 0) == users_before + 1, (
        f"expected Users to increment by exactly 1, got {users_before} -> {after.get('Users')}"
    )

    unpriv, unpriv_arn = _unprivileged_client(ctx)
    code, message = _error(lambda: unpriv.get_account_summary())
    assert code == "AccessDenied", f"expected AccessDenied for a zero-permission caller, got {code}"
    # Only the authorization id AWS appends varies per call.
    assert message == _no_policy_denial(unpriv_arn, "GetAccountSummary", message), (
        f"expected AWS's no-policy denial of iam:GetAccountSummary; got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
