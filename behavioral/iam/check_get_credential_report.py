"""get-credential-report."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-credential-report"
GROUP = 'credential_reports'
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
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. Raises if fn()
    succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _poll_until(ctx, fn, pred, timeout_s=90, interval_s=3):
    """Call fn() until pred(result) is truthy or timeout; return the last result."""
    deadline = time.monotonic() + timeout_s
    result = fn()
    while not pred(result) and time.monotonic() < deadline:
        time.sleep(interval_s)
        result = fn()
    return result


def _unprivileged_client(ctx):
    """A new zero-permission IAM user with an access key, returned as (IAM client for that user, its ARN).
    Access-key propagation is not instant, so STS is polled until the key is recognized."""
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


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Once GenerateCredentialReport completes, GetCredentialReport returns a text/csv body whose header
    row starts with user,arn; a zero-permission user gets AccessDenied and the exact no-policy message."""
    iam = ctx.client("iam")

    gen_result = _poll_until(
        ctx,
        lambda: iam.generate_credential_report(),
        lambda r: r.get("State") == "COMPLETE",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
    )
    assert gen_result.get("State") == "COMPLETE", f"expected COMPLETE, got {gen_result}"

    report = iam.get_credential_report()
    assert report["ReportFormat"] == "text/csv", f"expected text/csv, got {report['ReportFormat']}"
    # botocore already base64-decodes the wire "blob" payload for us, so report["Content"] is the
    # raw report bytes -- decoding it AGAIN with base64 would corrupt it. Just decode as UTF-8 text.
    content = report["Content"]
    csv_text = content.decode("utf-8") if isinstance(content, bytes) else content
    header = csv_text.splitlines()[0]
    assert header.startswith("user,arn"), f"unexpected credential-report CSV header: {header!r}"

    unpriv, unpriv_arn = _unprivileged_client(ctx)
    # A key STS already accepts can still be InvalidClientTokenId to IAM while it propagates.
    code, message = _poll_until(
        ctx,
        lambda: _error(lambda: unpriv.get_credential_report()),
        lambda r: r[0] != "InvalidClientTokenId",
        timeout_s=_budget_s(ctx, 120.0),
        interval_s=2,
    )
    assert code == "AccessDenied", f"expected AccessDenied for a zero-permission caller, got {code}"
    # Only the authorization id AWS appends varies per call.
    assert message == _no_policy_denial(unpriv_arn, "GetCredentialReport", message), (
        f"expected AWS's no-policy denial of iam:GetCredentialReport; got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
