"""delete-managed-login-branding-rejects-delete-and-update-after-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-managed-login-branding-rejects-delete-and-update-after-delete"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]

_NOT_FOUND = ("ResourceNotFoundException", "ManagedLoginBranding does not exist.")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second DeleteManagedLoginBranding and an UpdateManagedLoginBranding on a style
    that was already deleted each fail with the identical not-found code and message;
    the deletion that made it dead already succeeded."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTier="ESSENTIALS",
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-client-")
    )["UserPoolClient"]["ClientId"]

    branding_id = idp.create_managed_login_branding(
        UserPoolId=pool_id, ClientId=client_id, UseCognitoProvidedValues=True
    )["ManagedLoginBranding"]["ManagedLoginBrandingId"]

    # positive control: the style is live and describable before the delete that kills it.
    before = idp.describe_managed_login_branding(UserPoolId=pool_id, ManagedLoginBrandingId=branding_id)[
        "ManagedLoginBranding"
    ]
    assert before["ManagedLoginBrandingId"] == branding_id, (
        f"expected the created style to describe, got {before!r}"
    )

    idp.delete_managed_login_branding(UserPoolId=pool_id, ManagedLoginBrandingId=branding_id)

    code, message = _error(
        lambda: idp.delete_managed_login_branding(UserPoolId=pool_id, ManagedLoginBrandingId=branding_id)
    )
    assert (code, message) == _NOT_FOUND, f"a second delete: expected {_NOT_FOUND}, got {(code, message)!r}"

    code2, message2 = _error(
        lambda: idp.update_managed_login_branding(
            UserPoolId=pool_id, ManagedLoginBrandingId=branding_id, UseCognitoProvidedValues=True
        )
    )
    assert (code2, message2) == _NOT_FOUND, (
        f"an update on the dead id: expected {_NOT_FOUND}, got {(code2, message2)!r}"
    )


def _error(fn):
    """Call fn(); return its (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
