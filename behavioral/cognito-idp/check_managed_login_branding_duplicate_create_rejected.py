"""managed-login-branding-duplicate-create-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "managed-login-branding-duplicate-create-rejected"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateManagedLoginBranding for a client with a style fails with
    ManagedLoginBrandingExistsException and its exact message and leaves the style as it was, while a
    client without one accepts the same call."""
    idp = ctx.client("cognito-idp")

    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-branddup-pool-"),
        UserPoolTier="ESSENTIALS",
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-branddup"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-branddup-client-")
    )["UserPoolClient"]["ClientId"]
    other_client_id = idp.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-branddup-client2-")
    )["UserPoolClient"]["ClientId"]

    branding_id = idp.create_managed_login_branding(
        UserPoolId=pool_id, ClientId=client_id, UseCognitoProvidedValues=True
    )["ManagedLoginBranding"]["ManagedLoginBrandingId"]

    # positive control: the style exists and is visible through an independent read before we
    # attempt the duplicate.
    before = idp.describe_managed_login_branding_by_client(
        UserPoolId=pool_id, ClientId=client_id
    )["ManagedLoginBranding"]
    assert before["ManagedLoginBrandingId"] == branding_id, (
        f"the created style is not visible by-client: {before!r}"
    )

    code, message = _error(
        lambda: idp.create_managed_login_branding(
            UserPoolId=pool_id, ClientId=client_id, UseCognitoProvidedValues=True
        )
    )
    assert code == "ManagedLoginBrandingExistsException", (
        f"a duplicate CreateManagedLoginBranding for a client that already has a style was "
        f"rejected with {code!r}, expected ManagedLoginBrandingExistsException"
    )
    expected = f"A ManagedLoginBranding already exists for client {client_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the rejected duplicate did not replace, duplicate or otherwise touch the
    # existing style -- an independent read still shows the SAME branding id and value.
    after = idp.describe_managed_login_branding_by_client(
        UserPoolId=pool_id, ClientId=client_id
    )["ManagedLoginBranding"]
    assert after["ManagedLoginBrandingId"] == branding_id, (
        f"the rejected duplicate create changed the branding id from {branding_id!r} to "
        f"{after['ManagedLoginBrandingId']!r}"
    )
    assert after["UseCognitoProvidedValues"] is True, (
        f"the rejected duplicate create changed UseCognitoProvidedValues: {after!r}"
    )

    # positive control: a client with no existing style accepts the identical call, proving the
    # rejection above is specific to "a style already exists" and not a blanket refusal -- and the
    # terminal read is independent, at the destination, not the create call's own response.
    idp.create_managed_login_branding(
        UserPoolId=pool_id, ClientId=other_client_id, UseCognitoProvidedValues=True
    )
    other = idp.describe_managed_login_branding_by_client(
        UserPoolId=pool_id, ClientId=other_client_id
    )["ManagedLoginBranding"]
    assert other["UseCognitoProvidedValues"] is True, (
        f"the positive control's style is not visible by-client: {other!r}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        err = err.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(
        f"expected the duplicate create to be rejected, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
