"""describe-terms-by-client-returns-client-scoped-document."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-terms-by-client-returns-client-scoped-document"
GROUP = "data-plane"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTermsByClient returns the terms document specifically associated
    with the given client, distinct from another client's terms of the same
    TermsName in the same pool."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)
    client_a = _create_client(ctx, pool_id, "a")
    client_b = _create_client(ctx, pool_id, "b")

    url_a = "https://terms-a.example.com/tou"
    url_b = "https://terms-b.example.com/tou"
    _create_terms(ctx, pool_id, client_a, "terms-of-use", url_a)
    _create_terms(ctx, pool_id, client_b, "terms-of-use", url_b)

    terms_b = idp.describe_terms_by_client(
        UserPoolId=pool_id, ClientId=client_b, TermsName="terms-of-use"
    )["Terms"]
    assert terms_b["ClientId"] == client_b, (
        f"expected DescribeTermsByClient(ClientId={client_b!r}) to echo that ClientId, "
        f"got {terms_b['ClientId']!r}"
    )
    assert terms_b["Links"]["cognito:default"] == url_b, (
        f"expected client_b's terms to link {url_b!r}, got {terms_b['Links']['cognito:default']!r}"
    )
    assert terms_b["Links"]["cognito:default"] != url_a, (
        f"client_b's terms document leaked client_a's link {url_a!r}"
    )

    terms_a = idp.describe_terms_by_client(
        UserPoolId=pool_id, ClientId=client_a, TermsName="terms-of-use"
    )["Terms"]
    assert terms_a["ClientId"] == client_a, (
        f"expected DescribeTermsByClient(ClientId={client_a!r}) to echo that ClientId, "
        f"got {terms_a['ClientId']!r}"
    )
    assert terms_a["Links"]["cognito:default"] == url_a, (
        f"expected client_a's terms to link {url_a!r}, got {terms_a['Links']['cognito:default']!r}"
    )


def _create_pool(ctx) -> str:
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-pool"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_client(ctx, pool_id: str, suffix: str) -> str:
    idp = ctx.client("cognito-idp")
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name(f"sim2real-client-{suffix}-")
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: idp.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))
    return client_id


def _create_terms(ctx, pool_id: str, client_id: str, terms_name: str, url: str) -> str:
    idp = ctx.client("cognito-idp")
    terms_id = idp.create_terms(
        UserPoolId=pool_id,
        ClientId=client_id,
        TermsName=terms_name,
        TermsSource="LINK",
        Enforcement="NONE",
        Links={"cognito:default": url},
    )["Terms"]["TermsId"]
    ctx.on_cleanup(lambda: idp.delete_terms(UserPoolId=pool_id, TermsId=terms_id))
    return terms_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
