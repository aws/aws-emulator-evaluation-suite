"""assume-role-with-web-identity-invalid-token-format-rejected."""
from __future__ import annotations

import json
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "assume-role-with-web-identity-invalid-token-format-rejected"
GROUP = "error-semantics"
SERVICES = ["sts"]

_NOT_A_JWT_MESSAGE = (
    "The ID Token provided is not a valid JWT. (You may see this error if you sent an Access Token)"
)


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """AssumeRoleWithWebIdentity with a WebIdentityToken that is not a JWT (no dot-separated
    segments) fails with InvalidIdentityToken and the exact "not a valid JWT" message, and
    GetCallerIdentity still reports the caller's account."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = ctx.account

    sim2real_tags = [{"Key": "sim2real", "Value": "true"}]

    issuer = _user_pool_issuer(ctx)
    client_id = ctx.unique_name("sim2real-behav-client-")
    oidc_arn = iam.create_open_id_connect_provider(
        Url=issuer, ClientIDList=[client_id], Tags=sim2real_tags
    )["OpenIDConnectProviderArn"]
    ctx.on_cleanup(lambda: iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=oidc_arn))

    role_name = ctx.unique_name("sim2real-behav-badfmtrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": oidc_arn},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {f"{issuer.removeprefix('https://')}:aud": client_id}
                },
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=sim2real_tags,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    def _call():
        return sts.assume_role_with_web_identity(
            RoleArn=role_arn,
            RoleSessionName="bad-format-session",
            WebIdentityToken="this-is-not-a-jwt-token-at-all",
        )

    code, message = _error_code_and_message(_call)
    # The message pins that this is specifically a malformed-JWT rejection, not some other member of
    # the InvalidIdentityToken family (e.g. a bad signature or an unrecognized issuer), which would
    # also return this same error code.
    assert (code, message) == ("InvalidIdentityToken", _NOT_A_JWT_MESSAGE), (
        f"expected InvalidIdentityToken for a non-JWT WebIdentityToken, got {code!r}: {message!r}"
    )

    # Positive control: STS itself is functioning; the rejection is specific to
    # this malformed token, not a blanket endpoint failure.
    identity = sts.get_caller_identity()
    assert identity["Account"] == account_id, (
        f"expected get_caller_identity to still report account {account_id!r}, "
        f"got {identity.get('Account')!r}"
    )


def _user_pool_issuer(ctx) -> str:
    """The issuer URL of a Cognito user pool this check owns, from CreateUserPool's own answer.

    An OIDC issuer every target serves, so no third-party identity provider is named or contacted.
    """
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-userpool-"))["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return f"https://cognito-idp.{ctx.region}.amazonaws.com/{pool_id}"


def _error_code_and_message(fn: Callable[[], Any]) -> tuple[str, str | None]:
    from botocore.exceptions import ClientError

    try:
        resp = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(
        "expected AssumeRoleWithWebIdentity to reject the malformed WebIdentityToken, "
        f"but the call succeeded and issued credentials: {resp.get('AssumedRoleUser')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
