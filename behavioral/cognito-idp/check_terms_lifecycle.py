"""terms-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "terms-lifecycle"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTerms is listable/describable directly and by client; update persists; delete removes all views."""
    cognito = ctx.client("cognito-idp")
    pool_id, client_id = _create_pool_and_client(ctx)

    created = cognito.create_terms(
        UserPoolId=pool_id,
        ClientId=client_id,
        TermsName="terms-of-use",
        TermsSource="LINK",
        Enforcement="NONE",
        Links={"cognito:default": "https://sim2real-behav.example.com/terms"},
    )["Terms"]
    terms_id = created["TermsId"]
    ctx.on_cleanup(
        lambda: _ignore_errors(lambda: cognito.delete_terms(UserPoolId=pool_id, TermsId=terms_id))
    )
    assert created["Links"]["cognito:default"] == "https://sim2real-behav.example.com/terms", (
        f"expected freshly-created Links to echo the LINK document, got {created['Links']!r}"
    )

    described = cognito.describe_terms(UserPoolId=pool_id, TermsId=terms_id)["Terms"]
    assert described["TermsId"] == terms_id, (
        f"expected DescribeTerms to return TermsId {terms_id!r}, got {described['TermsId']!r}"
    )
    assert described["Enforcement"] == "NONE", (
        f"expected Enforcement 'NONE' as created, got {described['Enforcement']!r}"
    )

    ids = {t["TermsId"] for t in cognito.list_terms(UserPoolId=pool_id)["Terms"]}
    assert terms_id in ids, f"expected {terms_id!r} in ListTerms results, got {ids!r}"

    by_client = _describe_terms_by_client_or_skip(
        cognito, ClientId=client_id, UserPoolId=pool_id, TermsName="terms-of-use"
    )
    assert by_client["TermsId"] == terms_id, (
        f"expected DescribeTermsByClient to return TermsId {terms_id!r}, got {by_client['TermsId']!r}"
    )

    cognito.update_terms(
        UserPoolId=pool_id,
        TermsId=terms_id,
        TermsName="terms-of-use",
        TermsSource="LINK",
        Enforcement="NONE",
        Links={"cognito:default": "https://sim2real-behav.example.com/terms-v2"},
    )
    updated = cognito.describe_terms(UserPoolId=pool_id, TermsId=terms_id)["Terms"]
    assert updated["Links"]["cognito:default"] == "https://sim2real-behav.example.com/terms-v2", (
        f"expected UpdateTerms to persist the new link, got {updated['Links']!r}"
    )

    cognito.delete_terms(UserPoolId=pool_id, TermsId=terms_id)

    code, message = _error(lambda: cognito.describe_terms(UserPoolId=pool_id, TermsId=terms_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "Terms does not exist.", (
        f"expected the exact DescribeTerms not-found message, got {message!r}"
    )

    ids_after = {t["TermsId"] for t in cognito.list_terms(UserPoolId=pool_id)["Terms"]}
    assert terms_id not in ids_after, (
        f"expected {terms_id!r} absent from ListTerms after delete, got {ids_after!r}"
    )

    code2, message2 = _error(
        lambda: _describe_terms_by_client_or_skip(
            cognito, ClientId=client_id, UserPoolId=pool_id, TermsName="terms-of-use"
        )
    )
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2}"
    assert message2 == "Terms does not exist.", (
        f"expected the exact DescribeTermsByClient not-found message, got {message2!r}"
    )

    code3, message3 = _error(
        lambda: cognito.update_terms(
            UserPoolId=pool_id,
            TermsId=terms_id,
            TermsName="terms-of-use",
            TermsSource="LINK",
            Enforcement="NONE",
            Links={"cognito:default": "https://sim2real-behav.example.com/terms-v3"},
        )
    )
    assert code3 == "ResourceNotFoundException", (
        f"expected UpdateTerms on a deleted TermsId to fail with ResourceNotFoundException, got {code3}"
    )
    assert message3 == "Terms does not exist.", (
        f"expected the exact UpdateTerms not-found message, got {message3!r}"
    )


def _create_pool_and_client(ctx):
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-client-")
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))
    return pool_id, client_id


def _ignore_errors(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """Run fn and return the (code, message) AWS refused it with. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _describe_terms_by_client_or_skip(cognito, **kwargs):
    try:
        return cognito.describe_terms_by_client(**kwargs)["Terms"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "UnknownOperationException":
            raise AssertionError(
                "DescribeTermsByClient isn't recognized by this account/region's control plane, "
                "even though the SDK models the operation"
            )
        raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
