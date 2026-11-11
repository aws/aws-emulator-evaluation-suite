"""user-attribute-empty-string-vs-absent-distinguished-on-get-user."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "user-attribute-empty-string-vs-absent-distinguished-on-get-user"
GROUP = "representation"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminUpdateUserAttributes with a blank value deletes a custom attribute: GetUser shows the
    key absent afterwards (as before it was set), while a non-blank value is shown present.

    Reference: https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminUpdateUserAttributes.html"""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": False,
                "RequireLowercase": False,
                "RequireNumbers": False,
                "RequireSymbols": False,
            }
        },
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    attr_name = "sim2realattr"
    idp.add_custom_attributes(
        UserPoolId=pool_id,
        CustomAttributes=[{"Name": attr_name, "AttributeDataType": "String", "Mutable": True}],
    )
    full_attr_name = f"custom:{attr_name}"

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2real-user-")
    password = "Sim2Real-Pass-987"
    idp.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)

    access_token = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )["AuthenticationResult"]["AccessToken"]

    before = idp.get_user(AccessToken=access_token)["UserAttributes"]
    before_names = {a["Name"] for a in before}
    assert full_attr_name not in before_names, (
        f"{full_attr_name} unexpectedly present before it was ever set: {before}"
    )

    idp.admin_update_user_attributes(
        UserPoolId=pool_id, Username=username, UserAttributes=[{"Name": full_attr_name, "Value": "sim2real-value"}]
    )
    present = _poll_attrs(idp, access_token, full_attr_name, expect_present=True)
    assert present == "sim2real-value", f"expected 'sim2real-value' for {full_attr_name}, got {present!r}"

    # A blank value is the documented delete: the key must vanish, not linger as Value=="".
    idp.admin_update_user_attributes(
        UserPoolId=pool_id, Username=username, UserAttributes=[{"Name": full_attr_name, "Value": ""}]
    )
    _poll_attrs(idp, access_token, full_attr_name, expect_present=False)


def _poll_attrs(idp, access_token: str, full_attr_name: str, *, expect_present: bool):
    """Poll GetUser until the attribute's presence matches `expect_present`, allowing for
    read-path propagation lag; return the attribute's value when present."""
    deadline = time.monotonic() + 30.0
    after_by_name: dict[str, str] = {}
    while time.monotonic() < deadline:
        after = idp.get_user(AccessToken=access_token)["UserAttributes"]
        after_by_name = {a["Name"]: a["Value"] for a in after}
        if (full_attr_name in after_by_name) == expect_present:
            return after_by_name.get(full_attr_name)
        time.sleep(3.0)
    if expect_present:
        raise AssertionError(f"{full_attr_name} never appeared as present (timed out polling GetUser)")
    raise AssertionError(f"{full_attr_name} still present after being set to '' (timed out polling GetUser)")




if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
