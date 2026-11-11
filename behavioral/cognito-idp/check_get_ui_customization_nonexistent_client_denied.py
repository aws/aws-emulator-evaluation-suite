"""get-ui-customization-nonexistent-client-denied."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-ui-customization-nonexistent-client-denied"
GROUP = "negative-classes"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetUICustomization rejects a ClientId that doesn't exist in the given user pool,
    instead of silently returning an empty/default customization for it."""
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-uicustom-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-uicustom"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    # GetUICustomization requires a domain to be associated with the pool
    domain = ctx.unique_name("sim2realuic").lower().replace("_", "-")
    cognito.create_user_pool_domain(Domain=domain, UserPoolId=pool_id)
    ctx.on_cleanup(lambda: cognito.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id))

    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-client-")
    )["UserPoolClient"]["ClientId"]

    bogus_client_id = "nonexistentclientid00000000000001"
    code, message = _error(
        lambda: cognito.get_ui_customization(UserPoolId=pool_id, ClientId=bogus_client_id)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = f"User pool client {bogus_client_id} does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # positive control: a real client id belonging to the pool succeeds
    resp = cognito.get_ui_customization(UserPoolId=pool_id, ClientId=client_id)
    assert resp["UICustomization"].get("CSS") is None

    # positive control: pool-level lookup (no ClientId) also succeeds
    resp_pool = cognito.get_ui_customization(UserPoolId=pool_id)
    assert "UICustomization" in resp_pool


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
