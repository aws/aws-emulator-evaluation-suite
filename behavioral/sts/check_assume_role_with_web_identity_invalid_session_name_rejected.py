"""assume-role-with-web-identity-invalid-session-name-rejected."""
from __future__ import annotations

import base64
import json
import time
import uuid

from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-with-web-identity-invalid-session-name-rejected"
GROUP = 'assume-role-with-web-identity'
SERVICES = ['sts']

_BAD_SESSION_NAME = "bad session name!"
_BAD_SESSION_NAME_MESSAGE = (
    f"1 validation error detected: Value '{_BAD_SESSION_NAME}' at 'roleSessionName' failed to "
    "satisfy constraint: Member must satisfy regular expression pattern: [\\w+=,.@-]*"
)


def _error(fn):
    """The (code, message) of the refusal ``fn`` raises; raises AssertionError when ``fn`` succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(
        f"expected AssumeRoleWithWebIdentity to be rejected, but it succeeded: {resp}"
    )


def _anonymous_client(ctx, service: str = "sts"):
    """Client that sends UNSIGNED requests -- for the STS operations that are genuinely
    unauthenticated (AssumeRoleWithWebIdentity / WithSAML)."""
    return ctx.client(
        service,
        config=Config(signature_version=UNSIGNED, retries={"max_attempts": 1}),
    )


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _fake_jwt(*, issuer: str, exp_offset_s: int = 3600) -> str:
    """A well-formed JWT whose signature is random bytes, so it parses but cannot validate
    against the issuer's JWKS."""
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT", "kid": uuid.uuid4().hex}
    payload = {
        "iss": issuer,
        "aud": "sim2real-behav-audience",
        "sub": "sim2real-behav-subject-" + uuid.uuid4().hex[:8],
        "iat": now,
        "exp": now + exp_offset_s,
    }
    return ".".join(
        [
            _b64url(json.dumps(header).encode()),
            _b64url(json.dumps(payload).encode()),
            _b64url(uuid.uuid4().bytes + uuid.uuid4().bytes),
        ]
    )


def _user_pool_issuer(ctx) -> str:
    """The OIDC issuer URL of a Cognito user pool this check creates, so no third-party
    identity provider is named or contacted."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-userpool-"))["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return f"https://cognito-idp.{ctx.region}.amazonaws.com/{pool_id}"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    r"""AssumeRoleWithWebIdentity rejects a RoleSessionName outside ``[\w+=,.@-]`` with
    ValidationError and the exact pattern message even though the token is also unusable,
    while a valid session name with the same token does not get ValidationError."""
    account = ctx.account
    role_arn = f"arn:aws:iam::{account}:role/{ctx.unique_name('sim2real-behav-oidc-role-')}"
    client = _anonymous_client(ctx, "sts")
    token = _fake_jwt(issuer=_user_pool_issuer(ctx))

    # Positive control: rules out a target that returns ValidationError for every call.
    control_code, _ = _error(
        lambda: client.assume_role_with_web_identity(
            RoleArn=role_arn,
            RoleSessionName=ctx.unique_name("sim2real-behav-sess-"),
            WebIdentityToken=token,
        )
    )
    assert control_code != "ValidationError", (
        f"expected the valid session name to clear request-shape validation and fail on "
        f"token validation instead, but it also got ValidationError: {control_code}"
    )

    refusal = _error(
        lambda: client.assume_role_with_web_identity(
            RoleArn=role_arn,
            RoleSessionName=_BAD_SESSION_NAME,
            WebIdentityToken=token,
        )
    )
    assert refusal == ("ValidationError", _BAD_SESSION_NAME_MESSAGE), (
        f"expected ValidationError, got {refusal!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
