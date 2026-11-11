"""describe-terms-by-client-cross-pool-client-not-found-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-terms-by-client-cross-pool-client-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTermsByClient with a ClientId from another user pool answers
    ResourceNotFoundException and the exact message even though terms of that name exist in the
    pool, while the same lookup for the owning client returns them."""
    cip = ctx.client("cognito-idp")
    pool_a = _create_pool(ctx)
    pool_b = _create_pool(ctx)
    client_a = _create_pool_client(ctx, pool_a)
    client_b = _create_pool_client(ctx, pool_b)

    cip.create_terms(
        UserPoolId=pool_a,
        ClientId=client_a,
        TermsName="terms-of-use",
        TermsSource="LINK",
        Enforcement="NONE",
        Links={"cognito:default": "https://example.com/terms-of-use"},
    )

    # client_b is a real app client of pool_b, and "terms-of-use" exists in pool_a for client_a,
    # so a missing terms document cannot explain this rejection.
    code, message = _error(
        lambda: cip.describe_terms_by_client(
            UserPoolId=pool_a, ClientId=client_b, TermsName="terms-of-use"
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = f"User pool client {client_b} does not exist in user pool {pool_a}."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # same cross-pool mismatch, second valid TermsName: the rejection does
    # not depend on which enum value was requested
    code_again, message_again = _error(
        lambda: cip.describe_terms_by_client(
            UserPoolId=pool_a, ClientId=client_b, TermsName="privacy-policy"
        )
    )
    assert code_again == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {code_again}"
    )
    assert message_again == expected_message, f"expected message {expected_message!r}, got {message_again!r}"

    # effect absent: the bad lookup did not disturb pool_a's real terms
    terms_list = cip.list_terms(UserPoolId=pool_a)["Terms"]
    assert len(terms_list) == 1, f"expected exactly 1 terms document in pool_a, got {terms_list}"
    assert terms_list[0]["TermsName"] == "terms-of-use", (
        f"expected the untouched terms-of-use document, got {terms_list[0]!r}"
    )

    # positive control 1: the client genuinely belongs to pool_b and is
    # describable through the ordinary, unrelated control-plane API — it is
    # a real client, just not one that belongs to pool_a
    described = cip.describe_user_pool_client(UserPoolId=pool_b, ClientId=client_b)
    assert described["UserPoolClient"]["ClientId"] == client_b, (
        f"expected client_b to describe as itself, got {described['UserPoolClient']}"
    )

    # positive control 2: the identical (pool, client, terms-name) triple
    # that genuinely matches still resolves normally
    resp = cip.describe_terms_by_client(
        UserPoolId=pool_a, ClientId=client_a, TermsName="terms-of-use"
    )
    assert resp["Terms"]["TermsName"] == "terms-of-use", (
        f"expected terms-of-use, got {resp['Terms']!r}"
    )
    assert resp["Terms"]["ClientId"] == client_a, (
        f"expected ClientId {client_a}, got {resp['Terms']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _create_pool(ctx):
    cip = ctx.client("cognito-idp")
    pool_id = cip.create_user_pool(
        PoolName=ctx.unique_name("sim2real-cog-pool-"),
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cip.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_pool_client(ctx, pool_id):
    cip = ctx.client("cognito-idp")
    return cip.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-cog-client-"),
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
