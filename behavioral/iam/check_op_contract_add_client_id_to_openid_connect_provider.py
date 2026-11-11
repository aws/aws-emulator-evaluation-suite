"""op-contract-add-client-id-to-openid-connect-provider."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-add-client-id-to-openid-connect-provider"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddClientIDToOpenIDConnectProvider adds a client ID that GetOpenIDConnectProvider then lists
    in ClientIDList; for an unknown provider ARN in the caller's account it fails with
    NoSuchEntity and its exact message."""
    iam = ctx.client("iam")

    # The check's own user pool is the issuer: IAM's certificate-thumbprint fetch reaches a host
    # the target serves, and the Url is distinct per run.
    oidc_url = _user_pool_issuer(ctx)

    created = iam.create_open_id_connect_provider(
        Url=oidc_url, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    provider_arn = created["OpenIDConnectProviderArn"]
    ctx.on_cleanup(lambda: iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn))

    client_id = ctx.unique_name("sim2real-client-")
    iam.add_client_id_to_open_id_connect_provider(
        OpenIDConnectProviderArn=provider_arn, ClientID=client_id
    )

    got = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn)
    assert client_id in got.get("ClientIDList", []), (
        f"expected {client_id} in ClientIDList, got {got.get('ClientIDList')}"
    )

    # IAM authorizes against the ARN's account segment before checking existence, so a
    # foreign-account ARN would get AccessDenied rather than NoSuchEntity.
    caller_account = ctx.client("sts").get_caller_identity()["Account"]
    bogus_arn = f"arn:aws:iam::{caller_account}:oidc-provider/sim2real-does-not-exist.example.com"
    code, message = _error(
        lambda: iam.add_client_id_to_open_id_connect_provider(
            OpenIDConnectProviderArn=bogus_arn, ClientID="whatever"
        )
    )
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    expected = f"OpenIDConnect Provider not found for arn {bogus_arn}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _user_pool_issuer(ctx) -> str:
    """Issuer URL of a Cognito user pool this check owns, so no third-party IdP is contacted."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-userpool-"))["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return f"https://cognito-idp.{ctx.region}.amazonaws.com/{pool_id}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
