"""get-ui-customization-nonexistent-client-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-ui-customization-nonexistent-client-rejected"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetUICustomization returns no CSS for a real unbranded client and fails with
    ResourceNotFoundException and its exact message for a ClientId not in the pool."""
    cognito = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)
    client_id = _create_client(ctx, pool_id)
    _create_domain(ctx, pool_id)

    # Positive control: a real client id of this pool succeeds even with no
    # branding ever applied (per API contract: returns an empty/default object).
    resp = cognito.get_ui_customization(UserPoolId=pool_id, ClientId=client_id)
    css = resp["UICustomization"].get("CSS")
    assert css is None, f"expected no CSS on an unbranded real client, got {css!r}"

    # Negative: syntactically-valid but never-registered client id for this pool.
    fake_client_id = "1" * 26
    code, message = _error(
        lambda: cognito.get_ui_customization(UserPoolId=pool_id, ClientId=fake_client_id)
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a nonexistent ClientId, got {code!r}"
    )
    expected = f"User pool client {fake_client_id} does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its botocore Error code and message. An unexpected SUCCESS raises, because
    a target that accepts input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_user_pool(ctx):
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
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


def _create_domain(ctx, pool_id):
    # GetUICustomization requires the pool to already have a domain associated with
    # it (real AWS rejects the call with InvalidParameterException otherwise: "There
    # has to be an existing domain associated with this user pool..."), so provision
    # a throwaway Cognito-prefix domain before exercising the positive-control path.
    cognito = ctx.client("cognito-idp")
    domain = ctx.unique_name("sim2real-domain-").lower().replace("_", "-")
    cognito.create_user_pool_domain(Domain=domain, UserPoolId=pool_id)
    ctx.on_cleanup(lambda: cognito.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id))
    return domain


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
