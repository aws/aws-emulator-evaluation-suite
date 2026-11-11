"""get-authorization-token-without-credentials-denied."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-authorization-token-without-credentials-denied"
GROUP = "overly-permissive"
SERVICES = ["ecr-public"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetAuthorizationToken from an IAM principal with no ecr-public permissions fails
    AccessDeniedException, while the privileged caller still gets a usable token."""
    iam = ctx.client("iam")
    ecrp = _ecrpub_client(ctx)

    user_name = ctx.unique_name("sim2real-noauth-")
    iam.create_user(
        UserName=user_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"]))

    restricted = _client_with_credentials(
        ctx, key["AccessKeyId"], key["SecretAccessKey"]
    )

    code, message = _poll_stable_error_code(
        lambda: restricted.get_authorization_token(),
        transient_codes={"InvalidClientTokenId", "UnrecognizedClientException"},
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert code == "AccessDeniedException", (
        f"expected AccessDeniedException for an unauthorized principal, got {code}"
    )
    expected_message = f"User: arn:aws:iam::{ctx.account}:user/{user_name} is not authorized to perform: ecr-public:GetAuthorizationToken on resource: * because no identity-based policy allows the ecr-public:GetAuthorizationToken action"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    token = ecrp.get_authorization_token()["authorizationData"]
    assert token["authorizationToken"], "expected a non-empty authorization token"
    assert "expiresAt" in token


def _ecrpub_client(ctx):
    """A ctx client for ecr-public pinned to us-east-1, the only region that serves it."""
    return ctx.client("ecr-public", region="us-east-1")


def _client_with_credentials(ctx, access_key_id: str, secret_access_key: str):
    """A ctx client for ecr-public in us-east-1 that signs as the given access key."""
    return ctx.client(
        "ecr-public",
        region="us-east-1",
        creds={"aws_access_key_id": access_key_id, "aws_secret_access_key": secret_access_key},
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_stable_error_code(fn, *, transient_codes, timeout_s: float, interval_s: float):
    """Poll fn() until it fails with a code outside transient_codes (e.g. new IAM
    credentials that haven't propagated yet), and return that stable code."""
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        last_code, last_code_msg = _error_code(fn)
        if last_code not in transient_codes:
            return last_code, last_code_msg
        time.sleep(interval_s)
    raise AssertionError(
        f"credentials never stabilized past transient codes {transient_codes} within "
        f"{timeout_s}s; last observed code: {last_code!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
