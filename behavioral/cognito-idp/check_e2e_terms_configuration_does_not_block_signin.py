"""e2e-terms-configuration-does-not-block-signin."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "e2e-terms-configuration-does-not-block-signin"
GROUP = "e2e"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Terms created with Enforcement NONE read back from DescribeTermsByClient, and a
    NEW_PASSWORD_REQUIRED sign-in on that client completes with tokens and no extra challenge, as
    does the next login."""
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-terms-pool-"),
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": False,
            }
        },
        UserPoolTags={"sim2real-check": CHECK},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-terms-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]

    created = cognito.create_terms(
        UserPoolId=pool_id,
        ClientId=client_id,
        TermsName="terms-of-use",
        TermsSource="LINK",
        Enforcement="NONE",
        Links={"cognito:default": "https://example.com/terms"},
    )["Terms"]
    terms_id = created["TermsId"]
    ctx.on_cleanup(lambda: cognito.delete_terms(UserPoolId=pool_id, TermsId=terms_id))
    assert created["Enforcement"] == "NONE", (
        f"CreateTerms echoed Enforcement={created['Enforcement']!r}, expected 'NONE'"
    )

    described = cognito.describe_terms_by_client(
        ClientId=client_id, UserPoolId=pool_id, TermsName="terms-of-use"
    )["Terms"]
    assert described["TermsId"] == terms_id, (
        f"DescribeTermsByClient returned TermsId={described['TermsId']!r}, expected {terms_id!r}"
    )
    assert described["Enforcement"] == "NONE", (
        f"DescribeTermsByClient returned Enforcement={described['Enforcement']!r}, expected 'NONE'"
    )
    assert described["Links"]["cognito:default"] == "https://example.com/terms", (
        f"DescribeTermsByClient returned Links={described.get('Links')!r}, expected the "
        "cognito:default link created above"
    )

    username = ctx.unique_name("s2rtermsuser")
    temp_password = "Temp0raryPassw0rd!"
    new_password = "Br4ndNewPassw0rd!"
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}],
        TemporaryPassword=temp_password,
        MessageAction="SUPPRESS",
        DesiredDeliveryMediums=["EMAIL"],
    )

    first = cognito.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": temp_password},
    )
    # The only challenge in play is the real NEW_PASSWORD_REQUIRED one -- never a terms step.
    assert first.get("ChallengeName") == "NEW_PASSWORD_REQUIRED", (
        f"InitiateAuth returned ChallengeName={first.get('ChallengeName')!r} for a fresh "
        "temporary-password user with terms configured, expected 'NEW_PASSWORD_REQUIRED' "
        "and no intervening terms-acceptance challenge"
    )

    completed = cognito.respond_to_auth_challenge(
        ClientId=client_id,
        ChallengeName="NEW_PASSWORD_REQUIRED",
        Session=first["Session"],
        ChallengeResponses={"USERNAME": username, "NEW_PASSWORD": new_password},
    )
    assert completed.get("ChallengeName") is None, (
        f"RespondToAuthChallenge for NEW_PASSWORD_REQUIRED returned an extra "
        f"ChallengeName={completed.get('ChallengeName')!r} instead of completing sign-in; "
        "terms configuration must never inject a step here"
    )
    assert "AccessToken" in completed["AuthenticationResult"], (
        f"RespondToAuthChallenge completed with no AccessToken in AuthenticationResult: "
        f"{completed.get('AuthenticationResult')!r}"
    )

    second = cognito.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": new_password},
    )
    assert second.get("ChallengeName") is None, (
        f"InitiateAuth with the new password returned ChallengeName="
        f"{second.get('ChallengeName')!r}, expected a direct sign-in with no terms step"
    )
    assert "AccessToken" in second["AuthenticationResult"], (
        f"InitiateAuth with the new password returned no AccessToken in "
        f"AuthenticationResult: {second.get('AuthenticationResult')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
