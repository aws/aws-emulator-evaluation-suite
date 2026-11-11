"""get-csv-header-matches-user-pool-schema."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-csv-header-matches-user-pool-schema"
GROUP = "data-plane"
SERVICES = ["cognito-idp"]

# The fixed set of standard-attribute CSV columns Amazon Cognito exposes for every user
# pool's import template, per
# https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-using-import-tool.html
_STANDARD_HEADER = {
    "name", "given_name", "family_name", "middle_name", "nickname", "preferred_username",
    "profile", "picture", "website", "email", "email_verified", "gender", "birthdate",
    "zoneinfo", "locale", "phone_number", "phone_number_verified", "address", "updated_at",
    "cognito:mfa_enabled", "cognito:username",
    # Empirically present on real AWS in addition to the documented set (supports
    # importing users with pre-hashed passwords).
    "password_hash",
}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCSVHeader returns column names corresponding exactly to the pool's standard
    attribute set plus any custom attribute added to the schema."""
    cognito = ctx.client("cognito-idp")
    custom_attr = "favoritecolor"

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        Schema=[
            {"Name": custom_attr, "AttributeDataType": "String", "Mutable": True, "Required": False}
        ],
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-pool"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    header = set(cognito.get_csv_header(UserPoolId=pool_id)["CSVHeader"])

    expected = _STANDARD_HEADER | {f"custom:{custom_attr}"}
    missing = expected - header
    extra = header - expected
    assert not missing and not extra, f"CSVHeader diff: missing={missing} extra={extra} full={sorted(header)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
