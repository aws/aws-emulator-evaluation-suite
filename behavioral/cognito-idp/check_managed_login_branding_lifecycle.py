"""managed-login-branding-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "managed-login-branding-lifecycle"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateManagedLoginBranding is describable directly/by-client, updates persist, delete removes both."""
    cognito = ctx.client("cognito-idp")
    pool_id, client_id = _create_pool_and_client(ctx)

    try:
        created = cognito.create_managed_login_branding(
            UserPoolId=pool_id, ClientId=client_id, UseCognitoProvidedValues=True
        )["ManagedLoginBranding"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "OperationNotEnabledException":
            raise
        # Managed login branding requires a hosted domain on the pool; create one and retry.
        domain = ctx.unique_name("sim2real-behav-brand").lower().replace("_", "-")
        cognito.create_user_pool_domain(Domain=domain, UserPoolId=pool_id)
        ctx.on_cleanup(
            lambda: _ignore_errors(lambda: cognito.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id))
        )
        created = cognito.create_managed_login_branding(
            UserPoolId=pool_id, ClientId=client_id, UseCognitoProvidedValues=True
        )["ManagedLoginBranding"]

    branding_id = created["ManagedLoginBrandingId"]
    ctx.on_cleanup(
        lambda: _ignore_errors(
            lambda: cognito.delete_managed_login_branding(UserPoolId=pool_id, ManagedLoginBrandingId=branding_id)
        )
    )
    assert created["UseCognitoProvidedValues"] is True, (
        f"expected UseCognitoProvidedValues=True on create, got {created['UseCognitoProvidedValues']!r}"
    )

    described = cognito.describe_managed_login_branding(
        UserPoolId=pool_id, ManagedLoginBrandingId=branding_id, ReturnMergedResources=True
    )["ManagedLoginBranding"]
    assert described["ManagedLoginBrandingId"] == branding_id, (
        f"expected DescribeManagedLoginBranding to return {branding_id!r}, got"
        f" {described['ManagedLoginBrandingId']!r}"
    )

    by_client = cognito.describe_managed_login_branding_by_client(UserPoolId=pool_id, ClientId=client_id)[
        "ManagedLoginBranding"
    ]
    assert by_client["ManagedLoginBrandingId"] == branding_id, (
        f"expected DescribeManagedLoginBrandingByClient to return {branding_id!r}, got"
        f" {by_client['ManagedLoginBrandingId']!r}"
    )

    cognito.update_managed_login_branding(
        UserPoolId=pool_id,
        ManagedLoginBrandingId=branding_id,
        UseCognitoProvidedValues=False,
        # Real AWS rejects UseCognitoProvidedValues=False unless Settings is also supplied (it
        # can't fall back to auto-generated Cognito-provided settings once you opt out of them).
        # DescribeManagedLoginBranding only includes "Settings" in the response when called with
        # ReturnMergedResources=True; without it, a pool using Cognito-provided defaults omits
        # the key entirely.
        Settings=described["Settings"],
    )
    updated = cognito.describe_managed_login_branding(
        UserPoolId=pool_id, ManagedLoginBrandingId=branding_id
    )["ManagedLoginBranding"]
    assert updated["UseCognitoProvidedValues"] is False, (
        f"expected UseCognitoProvidedValues=False after update, got {updated['UseCognitoProvidedValues']!r}"
    )

    cognito.delete_managed_login_branding(UserPoolId=pool_id, ManagedLoginBrandingId=branding_id)

    code, message = _error(
        lambda: cognito.describe_managed_login_branding(
            UserPoolId=pool_id, ManagedLoginBrandingId=branding_id
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = "ManagedLoginBranding does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    code2, message2 = _error(
        lambda: cognito.describe_managed_login_branding_by_client(UserPoolId=pool_id, ClientId=client_id)
    )
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2}"
    expected_message2 = f"ManagedLoginBranding for client {client_id} does not exist."
    assert message2 == expected_message2, (
        f"expected message {expected_message2!r}, got {message2!r}"
    )


def _create_pool_and_client(ctx):
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-client-")
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))
    return pool_id, client_id


def _ignore_errors(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
