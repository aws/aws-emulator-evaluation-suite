"""describe-terms-by-client-returns-linked-terms."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-terms-by-client-returns-linked-terms"
GROUP = "data-plane"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTermsByClient for a client with CreateTerms attached returns the terms
    document that was created for THAT client, not a same-named terms document
    belonging to a different client in the same pool."""
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    client_a = cognito.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-client-a-"), GenerateSecret=False
    )["UserPoolClient"]["ClientId"]
    client_b = cognito.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-client-b-"), GenerateSecret=False
    )["UserPoolClient"]["ClientId"]

    terms_a = cognito.create_terms(
        UserPoolId=pool_id,
        ClientId=client_a,
        TermsName="terms-of-use",
        TermsSource="LINK",
        Enforcement="NONE",
        Links={"cognito:default": "https://example.com/terms-a"},
    )["Terms"]
    terms_b = cognito.create_terms(
        UserPoolId=pool_id,
        ClientId=client_b,
        TermsName="terms-of-use",
        TermsSource="LINK",
        Enforcement="NONE",
        Links={"cognito:default": "https://example.com/terms-b"},
    )["Terms"]
    assert terms_a["TermsId"] != terms_b["TermsId"], (
        f"create_terms minted the same TermsId {terms_a['TermsId']!r} for two distinct "
        f"clients under the same TermsName"
    )

    described_b = cognito.describe_terms_by_client(
        ClientId=client_b, UserPoolId=pool_id, TermsName="terms-of-use"
    )["Terms"]

    assert described_b["TermsId"] == terms_b["TermsId"], (
        f"DescribeTermsByClient for client_b returned {described_b['TermsId']!r}, "
        f"expected {terms_b['TermsId']!r} (client_a's is {terms_a['TermsId']!r})"
    )
    assert described_b["Links"]["cognito:default"] == "https://example.com/terms-b", (
        f"DescribeTermsByClient for client_b returned link "
        f"{described_b['Links'].get('cognito:default')!r}, expected 'https://example.com/terms-b'"
    )
    assert described_b["Links"]["cognito:default"] != "https://example.com/terms-a", (
        "DescribeTermsByClient for client_b returned client_a's link, "
        "'https://example.com/terms-a' — the two clients' terms documents are not isolated"
    )

    # Positive control: client_a resolves to its own terms document.
    described_a = cognito.describe_terms_by_client(
        ClientId=client_a, UserPoolId=pool_id, TermsName="terms-of-use"
    )["Terms"]
    assert described_a["TermsId"] == terms_a["TermsId"], (
        f"DescribeTermsByClient for client_a returned {described_a['TermsId']!r}, "
        f"expected {terms_a['TermsId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
