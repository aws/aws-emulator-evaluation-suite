"""terms-by-client-lifecycle-create-update-describe."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "terms-by-client-lifecycle-create-update-describe"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTerms associated with a client, then updated, is reflected at
    each transition via DescribeTermsByClient."""
    cognito = ctx.client("cognito-idp")
    pool_id, client_id = _create_pool_and_client(ctx, cognito)

    original_links = {"cognito:default": "https://example.com/terms-of-use"}
    created = cognito.create_terms(
        UserPoolId=pool_id,
        ClientId=client_id,
        TermsName="terms-of-use",
        TermsSource="LINK",
        Enforcement="NONE",
        Links=original_links,
    )["Terms"]
    terms_id = created["TermsId"]
    assert created["Links"] == original_links, (
        f"expected CreateTerms to echo {original_links!r}, got {created['Links']!r}"
    )

    fetched = cognito.describe_terms_by_client(
        UserPoolId=pool_id, ClientId=client_id, TermsName="terms-of-use"
    )["Terms"]
    assert fetched["TermsId"] == terms_id, (
        f"expected DescribeTermsByClient to resolve TermsId {terms_id!r}, got {fetched['TermsId']!r}"
    )
    assert fetched["Links"] == original_links, (
        f"expected DescribeTermsByClient to reflect {original_links!r} right after CreateTerms, "
        f"got {fetched['Links']!r}"
    )

    updated_links = {"cognito:default": "https://example.com/updated-terms-of-use"}
    cognito.update_terms(
        UserPoolId=pool_id,
        TermsId=terms_id,
        TermsName="terms-of-use",
        TermsSource="LINK",
        Enforcement="NONE",
        Links=updated_links,
    )

    fetched_after_update = cognito.describe_terms_by_client(
        UserPoolId=pool_id, ClientId=client_id, TermsName="terms-of-use"
    )["Terms"]
    assert fetched_after_update["TermsId"] == terms_id, (
        f"expected DescribeTermsByClient to still resolve TermsId {terms_id!r} after UpdateTerms, "
        f"got {fetched_after_update['TermsId']!r}"
    )
    assert fetched_after_update["Links"] == updated_links, (
        f"expected DescribeTermsByClient to reflect the UpdateTerms links {updated_links!r}, "
        f"got {fetched_after_update['Links']!r}"
    )
    assert fetched_after_update["Links"] != original_links, (
        "DescribeTermsByClient still returned the pre-update links "
        f"{original_links!r} after UpdateTerms — the by-client view did not pick up the change"
    )


def _create_pool_and_client(ctx, cognito):
    pool_name = ctx.unique_name("sim2real-behav-terms-pool-")
    pool_id = cognito.create_user_pool(PoolName=pool_name)["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    client_name = ctx.unique_name("sim2real-behav-terms-client-")
    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id, ClientName=client_name, GenerateSecret=False
    )["UserPoolClient"]["ClientId"]
    return pool_id, client_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
