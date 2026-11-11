"""describe-terms-by-client-reflects-server-computed-effective-terms."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-terms-by-client-reflects-server-computed-effective-terms"
GROUP = "server-side"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two clients with terms under the same TermsName get distinct records: DescribeTermsByClient
    returns each client's own links and TermsId, and DescribeTerms by TermsId matches its owner."""
    idp = ctx.client("cognito-idp")

    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-terms-effective-pool-"),
        UserPoolTags={"sim2real": "true"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    client_a = idp.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-terms-effective-a-")
    )["UserPoolClient"]["ClientId"]
    client_b = idp.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-terms-effective-b-")
    )["UserPoolClient"]["ClientId"]

    terms_a = idp.create_terms(
        UserPoolId=pool_id,
        ClientId=client_a,
        TermsName="terms-of-use",
        TermsSource="LINK",
        Enforcement="NONE",
        Links={"cognito:default": "https://a.example.com/terms"},
    )["Terms"]
    terms_b = idp.create_terms(
        UserPoolId=pool_id,
        ClientId=client_b,
        TermsName="terms-of-use",
        TermsSource="LINK",
        Enforcement="NONE",
        Links={"cognito:default": "https://b.example.com/terms"},
    )["Terms"]

    assert terms_a["TermsId"] != terms_b["TermsId"], (
        f"expected distinct TermsId per client, got a={terms_a['TermsId']!r} "
        f"b={terms_b['TermsId']!r}"
    )

    effective_a = idp.describe_terms_by_client(
        UserPoolId=pool_id, ClientId=client_a, TermsName="terms-of-use"
    )["Terms"]
    effective_b = idp.describe_terms_by_client(
        UserPoolId=pool_id, ClientId=client_b, TermsName="terms-of-use"
    )["Terms"]

    assert effective_a["Links"] == {"cognito:default": "https://a.example.com/terms"}, (
        f"expected client A's own link, got {effective_a['Links']!r}"
    )
    assert effective_b["Links"] == {"cognito:default": "https://b.example.com/terms"}, (
        f"expected client B's own link, got {effective_b['Links']!r}"
    )
    assert effective_a["TermsId"] == terms_a["TermsId"], (
        f"expected effective_a TermsId {terms_a['TermsId']!r}, got {effective_a['TermsId']!r}"
    )
    assert effective_b["TermsId"] == terms_b["TermsId"], (
        f"expected effective_b TermsId {terms_b['TermsId']!r}, got {effective_b['TermsId']!r}"
    )

    by_id_a = idp.describe_terms(TermsId=terms_a["TermsId"], UserPoolId=pool_id)["Terms"]
    assert by_id_a["Links"] == effective_a["Links"], (
        f"expected DescribeTerms Links to match DescribeTermsByClient Links "
        f"{effective_a['Links']!r}, got {by_id_a['Links']!r}"
    )
    assert by_id_a["ClientId"] == client_a, (
        f"expected DescribeTerms ClientId {client_a!r}, got {by_id_a['ClientId']!r}"
    )

    assert by_id_a["Links"] != effective_b["Links"], (
        f"expected client A's TermsId to disagree with client B's Links, "
        f"but both were {by_id_a['Links']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
