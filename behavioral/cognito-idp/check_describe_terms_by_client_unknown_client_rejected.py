"""describe-terms-by-client-unknown-client-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-terms-by-client-unknown-client-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTermsByClient returns the terms for the client they were created against and fails
    with ResourceNotFoundException and its exact message for a client id not in the pool."""
    cognito = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)
    client_id = _create_client(ctx, pool_id)

    cognito.create_terms(
        UserPoolId=pool_id,
        ClientId=client_id,
        TermsName="terms-of-use",
        TermsSource="LINK",
        Enforcement="NONE",
        Links={"cognito:default": "https://example.com/terms"},
    )
    terms_id = None
    try:
        # Positive control: real client + real terms name succeeds.
        resp = cognito.describe_terms_by_client(
            UserPoolId=pool_id, ClientId=client_id, TermsName="terms-of-use"
        )
        terms_id = resp["Terms"]["TermsId"]
        assert resp["Terms"]["ClientId"] == client_id, (
            f"expected ClientId {client_id}, got {resp['Terms']['ClientId']}"
        )
        assert resp["Terms"]["TermsName"] == "terms-of-use", (
            f"expected TermsName terms-of-use, got {resp['Terms']['TermsName']}"
        )

        # Negative: a syntactically valid but never-registered client id.
        fake_client_id = "0" * 26
        code, message = _error(
            lambda: cognito.describe_terms_by_client(
                UserPoolId=pool_id, ClientId=fake_client_id, TermsName="terms-of-use"
            )
        )
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException for an unregistered client id, got {code}"
        )
        expected = f"User pool client {fake_client_id} does not exist."
        assert message == expected, (
            f"expected the exact ResourceNotFoundException message {expected!r}, got {message!r}"
        )
    finally:
        if terms_id is not None:
            cognito.delete_terms(UserPoolId=pool_id, TermsId=terms_id)


def _error(fn) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_user_pool(ctx):
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-pool-"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_client(ctx, pool_id):
    cognito = ctx.client("cognito-idp")
    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))
    return client_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
