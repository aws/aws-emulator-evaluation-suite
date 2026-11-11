"""set-security-token-service-preferences."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-security-token-service-preferences"
GROUP = 'sts_preferences'
SERVICES = ['iam']


def _error(fn):
    """(code, message) of the refused call; an unexpected success is a failure."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _token_version(iam) -> int:
    """The account's GlobalEndpointTokenVersion (1 or 2); the modeled key must be present."""
    summary = iam.get_account_summary()["SummaryMap"]
    assert "GlobalEndpointTokenVersion" in summary, (
        f"GetAccountSummary.SummaryMap is missing the modeled GlobalEndpointTokenVersion key: "
        f"{sorted(summary)}"
    )
    return int(summary["GlobalEndpointTokenVersion"])


def _poll_token_version(iam, *, expected: int, timeout_s: float = 30.0) -> int:
    """Poll until the token version equals `expected`; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = _token_version(iam)
    while last != expected:
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"GlobalEndpointTokenVersion did not reach {expected} within {timeout_s}s; "
                f"last observed {last!r}"
            )
        time.sleep(2.0)
        last = _token_version(iam)
    return last


def _unprivileged_client(ctx):
    """(IAM client, ARN) for a new zero-permission user with an access key.

    Access keys propagate with a delay, so STS is polled until the key is recognized.
    """
    iam = ctx.client("iam")
    user_name = ctx.unique_name("nopriv-")
    user_arn = iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])[
        "User"]["Arn"]

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
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("InvalidClientTokenId", "InvalidAccessKeyId"):
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"the minted access key was never recognized; last {code!r}")
            time.sleep(3)
    return ctx.client("iam", creds=creds), user_arn


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


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:sts-token-preferences")
def run(ctx) -> None:
    """SetSecurityTokenServicePreferences(v2Token) shows up in GetAccountSummary; a zero-permission
    user's attempt to flip it back is AccessDenied with no effect; restore and re-apply succeed."""
    iam = ctx.client("iam")

    # Account-wide singleton: restore the installed value, not the documented v1Token default.
    baseline = _token_version(iam)
    ctx.on_cleanup(
        lambda: iam.set_security_token_service_preferences(
            GlobalEndpointTokenVersion=f"v{baseline}Token"
        )
    )

    resp = iam.set_security_token_service_preferences(GlobalEndpointTokenVersion="v2Token")
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected 200 from a privileged SetSecurityTokenServicePreferences call, got "
        f"{resp['ResponseMetadata']}"
    )
    observed = _poll_token_version(iam, expected=2)
    assert observed == 2, f"GlobalEndpointTokenVersion did not become 2 after the write, got {observed!r}"

    # Request the opposite value so a write that slipped through would be visible.
    unpriv, _unpriv_arn = _unprivileged_client(ctx)
    code, message = _error(
        lambda: unpriv.set_security_token_service_preferences(GlobalEndpointTokenVersion="v1Token")
    )
    assert code == "AccessDenied", f"expected AccessDenied for a zero-permission caller, got {code}"
    expected = _with_authorization_details(
        f"User: {_unpriv_arn} is not authorized to perform: iam:SetSecurityTokenServicePreferences "
        f"on resource: * because no identity-based policy allows the "
        f"iam:SetSecurityTokenServicePreferences action",
        message,
    )
    assert message == expected, f"expected the exact AccessDenied message {expected!r}, got {message!r}"
    after_denied = _token_version(iam)
    assert after_denied == 2, (
        f"denied write from a zero-permission caller changed GlobalEndpointTokenVersion: "
        f"{after_denied!r}"
    )

    iam.set_security_token_service_preferences(GlobalEndpointTokenVersion=f"v{baseline}Token")
    restored = _poll_token_version(iam, expected=baseline)
    assert restored == baseline, f"expected restore to {baseline}, got {restored!r}"

    resp2 = iam.set_security_token_service_preferences(GlobalEndpointTokenVersion="v2Token")
    assert resp2["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected 200 re-applying v2Token after restore, got {resp2['ResponseMetadata']}"
    )
    final = _poll_token_version(iam, expected=2)
    assert final == 2, f"expected GlobalEndpointTokenVersion=2 after re-apply, got {final!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
