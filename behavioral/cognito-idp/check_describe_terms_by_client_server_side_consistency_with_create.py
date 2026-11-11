"""describe-terms-by-client-server-side-consistency-with-create."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-terms-by-client-server-side-consistency-with-create"
GROUP = "server-side"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTermsByClient reflects a preceding CreateTerms with no caching drift,
    and once the Terms are deleted the same client-scoped read stops resolving it."""
    cognito = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx, cognito)
    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-client-")
    )["UserPoolClient"]["ClientId"]

    links = {"cognito:default": "https://example.com/terms-of-use"}
    created = cognito.create_terms(
        UserPoolId=pool_id,
        ClientId=client_id,
        TermsName="terms-of-use",
        TermsSource="LINK",
        Enforcement="NONE",
        Links=links,
    )["Terms"]

    described = cognito.describe_terms_by_client(
        UserPoolId=pool_id, ClientId=client_id, TermsName="terms-of-use"
    )["Terms"]

    assert described["TermsId"] == created["TermsId"], (
        f"expected TermsId {created['TermsId']!r} from the preceding CreateTerms, "
        f"got {described['TermsId']!r}"
    )
    assert described["TermsSource"] == "LINK", (
        f"expected TermsSource 'LINK', got {described['TermsSource']!r}"
    )
    assert described["Enforcement"] == "NONE", (
        f"expected Enforcement 'NONE', got {described['Enforcement']!r}"
    )
    assert described["Links"] == links, f"expected Links {links!r}, got {described['Links']!r}"
    assert described["ClientId"] == client_id, (
        f"expected ClientId {client_id!r}, got {described['ClientId']!r}"
    )

    # A second, later read must be byte-for-byte identical -- no caching drift.
    described_again = cognito.describe_terms_by_client(
        UserPoolId=pool_id, ClientId=client_id, TermsName="terms-of-use"
    )["Terms"]
    assert described_again == described, (
        f"repeated DescribeTermsByClient drifted: first read {described!r}, "
        f"second read {described_again!r}"
    )

    # Delete proves gone: an independent read of the same client-scoped document
    # must stop resolving it once the Terms record is removed.
    cognito.delete_terms(UserPoolId=pool_id, TermsId=created["TermsId"])
    code_after_delete, message_after_delete = _error(
        lambda: cognito.describe_terms_by_client(
            UserPoolId=pool_id, ClientId=client_id, TermsName="terms-of-use"
        )
    )
    assert code_after_delete == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for DescribeTermsByClient after DeleteTerms, "
        f"got {code_after_delete!r}"
    )
    assert message_after_delete == "Terms does not exist.", (
        f"expected the exact ResourceNotFoundException message 'Terms does not exist.', got {message_after_delete!r}"
    )


def _create_user_pool(ctx, cognito, **overrides):
    params = {
        "PoolName": ctx.unique_name("sim2real-behav-pool-"),
        "UserPoolTags": {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    }
    params.update(overrides)
    pool_id = cognito.create_user_pool(**params)["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected DescribeTermsByClient to fail after DeleteTerms, but it SUCCEEDED "
        f"and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
