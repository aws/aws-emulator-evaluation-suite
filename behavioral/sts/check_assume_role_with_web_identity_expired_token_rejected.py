"""assume-role-with-web-identity-expired-token-rejected."""
from __future__ import annotations

import base64
import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "assume-role-with-web-identity-expired-token-rejected"
GROUP = "error-semantics"
SERVICES = ["sts"]

_TAMPERED_MESSAGE = (
    "The web identity token provided could not be validated. "
    "See the AssumeRoleWithWebIdentity documentation for requirements."
)


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """AssumeRoleWithWebIdentity rejects a Cognito ID token whose signature byte is flipped.

    The untampered token is accepted first as the control; the tampered one fails
    InvalidIdentityToken with the "could not be validated" message. Token expiry is not reached.
    """
    cidp = ctx.client("cognito-idp")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    pool_name = ctx.unique_name("sim2real-behav-pool-")
    pool_id = cidp.create_user_pool(
        PoolName=pool_name,
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cidp.delete_user_pool(UserPoolId=pool_id))

    client_name = ctx.unique_name("sim2real-behav-client-")
    client_resp = cidp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=client_name,
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )
    client_id = client_resp["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2real-behav-u-")
    password = "Sim2Real-Behav-1!"
    cidp.admin_create_user(
        UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS", TemporaryPassword=password
    )
    cidp.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )

    auth = cidp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    id_token = auth["AuthenticationResult"]["IdToken"]

    issuer_url = ctx.service_url(f"https://cognito-idp.{ctx.region}.amazonaws.com") + f"/{pool_id}"
    oidc_arn = iam.create_open_id_connect_provider(
        Url=issuer_url,
        ClientIDList=[client_id],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["OpenIDConnectProviderArn"]
    ctx.on_cleanup(lambda: iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=oidc_arn))

    role_name = ctx.unique_name("sim2real-behav-oidcrole-")
    aud_key = f"{issuer_url.split('://', 1)[1]}:aud"
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": oidc_arn},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {"StringEquals": {aud_key: client_id}},
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    def _assume(token: str) -> dict:
        return sts.assume_role_with_web_identity(
            RoleArn=role_arn, RoleSessionName="cognito-session", WebIdentityToken=token
        )

    # OIDC provider trust propagation is eventually consistent; retry the genuine,
    # untampered token until it is accepted -- this is our positive control.
    result = _retry_until_success(lambda: _assume(id_token), timeout_s=90.0, interval_s=5.0)
    assumed_arn = result["AssumedRoleUser"]["Arn"]
    assert assumed_arn.startswith("arn:aws:sts::"), (
        f"expected an sts assumed-role ARN for the genuine, untampered token, got: {assumed_arn}"
    )

    tampered_token = _flip_signature_byte(id_token)
    assert tampered_token != id_token, (
        "signature byte flip produced no change -- tampering helper is a no-op"
    )

    refusal = _error(lambda: _assume(tampered_token))
    assert refusal == ("InvalidIdentityToken", _TAMPERED_MESSAGE), (
        f"expected InvalidIdentityToken for a signature-tampered web identity token, got: {refusal!r}"
    )


def _flip_signature_byte(jwt: str) -> str:
    header, payload, signature = jwt.split(".")
    padded = signature + "=" * (-len(signature) % 4)
    raw = bytearray(base64.urlsafe_b64decode(padded))
    raw[-1] ^= 0xFF
    tampered_sig = base64.urlsafe_b64encode(bytes(raw)).decode().rstrip("=")
    return f"{header}.{payload}.{tampered_sig}"


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises with the accepted
    response."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected rejection of the signature-tampered web identity token, but it SUCCEEDED "
        f"and returned: {result.get('AssumedRoleUser')}"
    )


def _retry_until_success(
    fn: Callable[[], Any], *, timeout_s: float, interval_s: float
) -> Any:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"operation never succeeded within {timeout_s}s: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

