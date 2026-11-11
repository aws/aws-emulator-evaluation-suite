"""terms-document-url-unicode-name-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "terms-document-url-unicode-name-preserved"
GROUP = "representation"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Terms document's unicode link URL created via CreateTerms is read back unchanged via DescribeTermsByClient."""
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-terms-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-terms-client-")
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))

    # Value pattern allows unicode letters/marks/symbols/numbers/punctuation (no whitespace).
    default_url = "https://\u4f8b\u3048.\u30c6\u30b9\u30c8/\u79c1\u306e\u898f\u5247?ref=\u2713&id=1"
    spanish_url = "https://terms.example.com/pol\u00edtica-de-privacidad"

    created = cognito.create_terms(
        UserPoolId=pool_id,
        ClientId=client_id,
        TermsName="privacy-policy",
        TermsSource="LINK",
        Enforcement="NONE",
        Links={"cognito:default": default_url, "cognito:spanish": spanish_url},
    )["Terms"]
    terms_id = created["TermsId"]
    ctx.on_cleanup(lambda: cognito.delete_terms(TermsId=terms_id, UserPoolId=pool_id))

    described = cognito.describe_terms_by_client(
        ClientId=client_id, UserPoolId=pool_id, TermsName="privacy-policy"
    )["Terms"]

    assert described["TermsId"] == terms_id, f"expected TermsId {terms_id!r}, got {described['TermsId']!r}"
    assert described["TermsName"] == "privacy-policy", (
        f"expected TermsName 'privacy-policy', got {described['TermsName']!r}"
    )
    assert described["Links"] == {
        "cognito:default": default_url,
        "cognito:spanish": spanish_url,
    }, "unicode terms links were not preserved byte-identical"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
