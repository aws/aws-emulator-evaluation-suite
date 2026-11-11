"""assume-role-with-web-identity-forged-token-rejected."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-with-web-identity-forged-token-rejected"
GROUP = 'overly-permissive'
SERVICES = ['sts']

_FORGED_MESSAGE = "We don't accept unsigned JWTs"

# example.com (RFC 2606) serves valid HTTPS, so CreateOpenIDConnectProvider's TLS fetch succeeds;
# a per-run path component keeps IAM's one-provider-per-URL constraint from colliding.
_ISSUER_HOST = "example.com"


def _fake_jwt(payload: dict) -> str:
    """Build an unsigned JWT-shaped token (header.payload.signature) so we
    can exercise AssumeRoleWithWebIdentity's claim parsing without needing
    a real signed identity provider token."""

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = b64(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    body = b64(json.dumps(payload).encode())
    return f"{header}.{body}."

@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssumeRoleWithWebIdentity rejects an unsigned, self-minted JWT with InvalidIdentityToken "We
    don't accept unsigned JWTs", even though its iss/aud claims satisfy the trust policy of a role
    that plain AssumeRole assumes."""

    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = ctx.account

    issuer_url = f"https://{_ISSUER_HOST}/{ctx.unique_name('oidc')}"
    audience = ctx.unique_name("sim2real-behav-aud-")

    provider_arn = iam.create_open_id_connect_provider(
        Url=issuer_url, ClientIDList=[audience], ThumbprintList=["0" * 40]
    )["OpenIDConnectProviderArn"]
    ctx.on_cleanup(lambda: _delete_oidc_provider(iam, provider_arn))

    role_name = ctx.unique_name("sim2real-behav-forged-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowMatchingWebIdentity",
                "Effect": "Allow",
                "Principal": {"Federated": provider_arn},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {"StringEquals": {f"{_ISSUER_HOST}:aud": audience}},
            },
            {
                "Sid": "AllowPlainAssumeRole",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            },
        ],
    }
    role_arn = _create_role_with_retry(iam, role_name, trust_policy)
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))

    # Positive control via plain AssumeRole, so the rejection below is due to the token.
    control_creds = _wait_for_assume_role(sts, RoleArn=role_arn, RoleSessionName="control-session")
    assert control_creds["AccessKeyId"], (
        f"positive control failed: plain AssumeRole against {role_arn} never returned "
        "credentials, so the role itself cannot be trusted as a control for the forged-"
        "token rejection below"
    )

    # Claims deliberately match the trust policy's Federated principal and `aud`
    # condition, isolating the missing signature as the only broken thing.
    token = _fake_jwt(
        {
            "iss": issuer_url,
            "aud": audience,
            "sub": "web-user-1",
            "iat": int(time.time()),
            "exp": int(time.time()) + 600,
        }
    )

    refusal = _error(
        lambda: sts.assume_role_with_web_identity(
            RoleArn=role_arn,
            RoleSessionName=ctx.unique_name("sim2real-behav-sess-"),
            WebIdentityToken=token,
        )
    )
    assert refusal == ("InvalidIdentityToken", _FORGED_MESSAGE), (
        f"unexpected refusal for a forged web identity token: {refusal!r}"
    )


def _error(fn):
    """(code, message) of the refusal ``fn`` raises; AssertionError when ``fn`` succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(
        "AssumeRoleWithWebIdentity ACCEPTED a forged, unsigned web identity token "
        "whose claims matched a real, genuinely-assumable role's trust policy, and "
        f"issued credentials: {resp.get('AssumedRoleUser')}"
    )


def _create_role_with_retry(
    iam, role_name: str, trust_policy: dict, timeout_s: float = 30.0, interval_s: float = 2.0
) -> str:
    """CreateRole can reject a just-created OIDC provider's ARN as an unknown
    trusted principal for a brief window while the provider propagates
    through IAM; retry MalformedPolicyDocument until it clears."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return iam.create_role(
                RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
            )["Role"]["Arn"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            if code != "MalformedPolicyDocument" or time.monotonic() >= deadline:
                raise AssertionError(
                    f"CreateRole rejected the OIDC-provider trust policy ({code}): {message}"
                ) from exc
            time.sleep(interval_s)


def _wait_for_assume_role(sts_client, timeout_s: float = 30.0, interval_s: float = 2.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return sts_client.assume_role(**kwargs)["Credentials"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "AccessDenied":
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"assume_role never became permitted within {timeout_s}s: {last_err}")


def _delete_oidc_provider(iam, arn: str) -> None:
    try:
        iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_role(iam, name: str) -> None:
    try:
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
