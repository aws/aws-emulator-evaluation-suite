"""xsvc-iam-2-secretsmanager-access-denied-status-code-differs-by-protocol."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-iam-2-secretsmanager-access-denied-status-code-differs-by-protocol"
GROUP = "auth_enforcement"
SERVICES = ["iam", "secretsmanager"]


def _error_code_and_status(fn):
    """(Error.Code, HTTPStatusCode, Error.Message) of a ClientError; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return (err.get("Code"), exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
                err.get("Message", ""))
    raise AssertionError(f"expected the call to be denied, but it SUCCEEDED: {result!r}")


def _client_for_access_key(ctx, service, access_key_id, secret_access_key):
    """A client signing as the minted IAM user with a plain access key."""
    return ctx.client(service, creds={"aws_access_key_id": access_key_id,
                                      "aws_secret_access_key": secret_access_key})


def _poll_until_propagated(probe, *, timeout_s=60.0, interval_s=3.0):
    """Poll past the InvalidClientTokenId/SignatureDoesNotMatch a fresh access key draws before IAM
    propagates it, then return the real outcome."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        code, status, message = probe()
        last = (code, status, message)
        if code not in (
            "InvalidClientTokenId",
            "SignatureDoesNotMatch",
            "UnrecognizedClientException",
        ):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"access key never propagated within {timeout_s}s; last saw {last!r}")


@tags(
    "axis:rejection",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
    "cap:c7",
)
def run(ctx) -> None:
    """One unauthorized user is denied by IAM (awsQuery) with AccessDenied at HTTP 403 and by
    Secrets Manager (awsJson1_1) with AccessDeniedException at HTTP 400, with exact messages.
    """
    iam = ctx.client("iam")
    secretsmanager = ctx.client("secretsmanager")

    # --- Positive controls: the account's own credentials are not the denied principal, so both
    #     calls must succeed before we trust either rejection below.
    iam.list_users(MaxItems=1)
    secretsmanager.list_secrets(MaxResults=1)

    user_name = ctx.unique_name("sim2real-xsvc-iamsm-denied-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real:managed", "Value": "true"}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"])
    )

    as_denied_iam = _client_for_access_key(
        ctx, "iam", key["AccessKeyId"], key["SecretAccessKey"]
    )
    as_denied_sm = _client_for_access_key(
        ctx, "secretsmanager", key["AccessKeyId"], key["SecretAccessKey"]
    )

    iam_code, iam_status, iam_msg = _poll_until_propagated(
        lambda: _error_code_and_status(lambda: as_denied_iam.list_users(MaxItems=1))
    )
    assert iam_code == "AccessDenied", (
        f"expected IAM's awsQuery protocol to deny an unauthorized ListUsers with exactly "
        f"'AccessDenied', got {iam_code!r}"
    )
    user_arn = f"arn:aws:iam::{ctx.account}:user/{user_name}"
    want = (f"User: {user_arn} is not authorized to perform: iam:ListUsers on resource: "
            f"arn:aws:iam::{ctx.account}:user/ because no identity-based policy allows the "
            f"iam:ListUsers action")
    assert iam_msg == want, f"IAM denial message: expected {want!r}, got {iam_msg!r}"
    assert iam_status == 403, (
        f"expected IAM's awsQuery AccessDenied to carry HTTP 403, got {iam_status!r}"
    )

    sm_code, sm_status, sm_msg = _poll_until_propagated(
        lambda: _error_code_and_status(lambda: as_denied_sm.list_secrets(MaxResults=1))
    )
    assert sm_code == "AccessDeniedException", (
        f"expected Secrets Manager's awsJson1_1 protocol to deny an unauthorized ListSecrets "
        f"with exactly 'AccessDeniedException', got {sm_code!r}"
    )
    want = (f"User: {user_arn} is not authorized to perform: secretsmanager:ListSecrets "
            f"because no identity-based policy allows the secretsmanager:ListSecrets action")
    assert sm_msg == want, f"Secrets Manager denial message: expected {want!r}, got {sm_msg!r}"
    assert sm_status == 400, (
        f"expected Secrets Manager's awsJson1_1 AccessDeniedException to carry HTTP 400 (the "
        f"JSON-RPC convention, not 403), got {sm_status!r}"
    )

    # --- The two services disagree on status for the identical denial reason and the identical
    #     caller: the variable is the target's protocol, not the principal or the account.
    assert iam_status != sm_status, (
        f"the whole claim is that these differ by protocol; both came back {iam_status!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
