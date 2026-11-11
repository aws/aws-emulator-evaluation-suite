"""generate-credential-report."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "generate-credential-report"
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


# Codes IAM returns while a freshly minted access key has not reached every replica yet.
_UNRECOGNIZED = ("InvalidClientTokenId", "InvalidAccessKeyId")


def _budget_s(ctx, cap_s):
    """A poll's timeout, bounded by the runner's remaining time so the poll fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


def _outcome(fn):
    """The botocore Error.Code fn() raises, or "OK" when it succeeds -- never a falsy value."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return "OK"


def _poll_until(fn, pred, timeout_s=90, interval_s=3):
    deadline = time.monotonic() + timeout_s
    result = fn()
    while not pred(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not reached within {timeout_s}s; last result {result!r}")
        time.sleep(interval_s)
        result = fn()
    return result


def _target_client(ctx, service, creds):
    return ctx.client(service, creds=creds)


def _unprivileged_client(ctx):
    """Create a zero-permission IAM user with an access key; return (iam_client, user_name).

    Access-key propagation is not instant, so STS is polled until the key is recognized.
    """
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-nopriv-")
    iam.create_user(UserName=user_name)

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
    unpriv_sts = _target_client(ctx, "sts", creds)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            unpriv_sts.get_caller_identity()
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in (
                "InvalidClientTokenId",
                "InvalidAccessKeyId",
            ):
                break
            time.sleep(3)
    return _target_client(ctx, "iam", creds), user_name


def _denial(fn):
    """(Error.Code, Error.Message) of a call real AWS refuses; an unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GenerateCredentialReport reaches COMPLETE and GetCredentialReport returns a non-empty body;
    a zero-permission user gets AccessDenied and the exact no-policy message, and succeeds once granted it."""
    iam = ctx.client("iam")

    # The documented usage is to call GenerateCredentialReport repeatedly until State is COMPLETE.
    result = _poll_until(
        lambda: iam.generate_credential_report(),
        lambda r: r.get("State") == "COMPLETE",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
    )
    assert result["State"] == "COMPLETE", f"expected COMPLETE, got {result}"

    report = iam.get_credential_report()
    assert report["Content"], "expected a non-empty report body once COMPLETE"

    unpriv, unpriv_user = _unprivileged_client(ctx)
    # A minted access key reaches STS and IAM at different moments; retry only while IAM still
    # reports the key unrecognized, then grade the first answer it gives.
    code = _poll_until(
        lambda: _outcome(lambda: unpriv.generate_credential_report()),
        lambda c: c not in _UNRECOGNIZED,
        timeout_s=60,
        interval_s=3,
    )
    _, denied_msg = _poll_until(
        lambda: _denial(lambda: unpriv.generate_credential_report()),
        lambda r: r[0] not in _UNRECOGNIZED,
        timeout_s=60,
        interval_s=3,
    )
    # Only the authorization id AWS appends varies per call.
    unpriv_arn = f"arn:aws:iam::{ctx.account}:user/{unpriv_user}"
    assert denied_msg == _no_policy_denial(unpriv_arn, "GenerateCredentialReport", denied_msg), (
        f"expected AWS's no-policy denial of iam:GenerateCredentialReport; got {denied_msg!r}"
    )
    assert code == "AccessDenied", f"expected AccessDenied for a zero-permission caller, got {code}"

    # Granting the one action proves the denial came from the missing grant, not a blanket refusal.
    grant_name = ctx.unique_name("sim2real-behav-allow-gcr-")
    iam.put_user_policy(
        UserName=unpriv_user,
        PolicyName=grant_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "iam:GenerateCredentialReport", "Resource": "*"}],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=unpriv_user, PolicyName=grant_name))

    restored_code = _poll_until(
        lambda: _outcome(lambda: unpriv.generate_credential_report()),
        lambda c: c != "AccessDenied" and c not in _UNRECOGNIZED,
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
    )
    assert restored_code == "OK", (
        f"expected the grant to allow generate_credential_report once effective, got {restored_code}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
