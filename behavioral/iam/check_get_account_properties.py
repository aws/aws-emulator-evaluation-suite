"""get-account-properties."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-account-properties"
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


def _budget_s(ctx, cap_s):
    """A poll's timeout, bounded by the runner's remaining time so the poll fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


def _error(fn):
    """Call fn(); return the botocore (Code, Message) of the ClientError it raises. An unexpected
    SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _unprivileged_client(ctx):
    """A brand-new IAM user with ZERO attached permissions + a minted access key, returned as (an
    IAM client authenticated as that user, its ARN). A fresh IAM principal implicit-denies
    everything, so any call through it is expected AccessDenied. Cleanup is registered."""
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
    return ctx.client("iam", creds=creds), user_arn


def _error_once_propagated(fn, *, timeout_s=90, interval_s=3):
    """`_error(fn)`, tolerating access-key propagation lag.

    Access-key propagation is per-service, not global: STS can recognise a key while IAM's own
    replica of the same credential still answers `InvalidClientTokenId`. So this polls `fn` itself,
    the actual call under test, and only tolerates the two propagation-lag codes; anything else
    returns immediately. A timeout raises rather than returning a code that might still be lag.
    The same interval and deadline apply on every target.
    """
    deadline = time.monotonic() + timeout_s
    got = _error(fn)
    while got[0] in ("InvalidClientTokenId", "InvalidAccessKeyId"):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"unprivileged access key not recognized by iam within {timeout_s}s "
                f"(still {got[0]!r}); cannot distinguish AccessDenied from unpropagated credentials"
            )
        time.sleep(interval_s)
        got = _error(fn)
    return got


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetAccountProperties returns a Properties map for the check's caller and fails with
    AccessDenied and the exact no-policy message for a zero-permission user."""
    iam = ctx.client("iam")
    if not hasattr(iam, "get_account_properties"):
        raise AssertionError("get_account_properties not in public IAM API")
    resp = iam.get_account_properties()
    assert "Properties" in resp, f"missing Properties: {resp}"
    assert isinstance(resp["Properties"], dict), (
        f"expected Properties to be a dict, got {type(resp['Properties'])}: {resp['Properties']!r}"
    )

    unpriv, unpriv_arn = _unprivileged_client(ctx)
    code, message = _error_once_propagated(
        lambda: unpriv.get_account_properties(), timeout_s=_budget_s(ctx, 90.0)
    )
    assert code == "AccessDenied", f"expected AccessDenied for a zero-permission caller, got {code}"
    # Only the authorization id AWS appends varies per call.
    assert message == _no_policy_denial(unpriv_arn, "GetAccountProperties", message), (
        f"expected AWS's no-policy denial of iam:GetAccountProperties; got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
