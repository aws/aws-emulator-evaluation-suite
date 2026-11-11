"""describe-terms-by-client-nonexistent-client-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-terms-by-client-nonexistent-client-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTermsByClient with a TermsName outside the terms-of-use|privacy-policy pattern is
    refused with InvalidParameterException and the exact message, a valid name with no terms answers
    ResourceNotFoundException "Terms does not exist.", and after CreateTerms it returns them."""
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-client-")
    )["UserPoolClient"]["ClientId"]

    # boundary 1: TermsName doesn't match the fixed enum pattern -> InvalidParameterException,
    # a pure parameter-shape failure detected before any client/terms lookup occurs
    code_bad_name, message_bad_name = _error(
        lambda: cognito.describe_terms_by_client(
            UserPoolId=pool_id, ClientId=client_id, TermsName="not-a-valid-terms-name"
        )
    )
    assert code_bad_name == "InvalidParameterException", (
        f"expected InvalidParameterException for a malformed TermsName, got {code_bad_name}"
    )
    expected_bad_name = (
        "1 validation error detected: Value 'not-a-valid-terms-name' at 'termsName' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: ^(terms-of-use|privacy-policy)$"
    )
    assert message_bad_name == expected_bad_name, (
        f"expected message {expected_bad_name!r}, got {message_bad_name!r}"
    )

    # boundary 2 (contrast): a syntactically valid TermsName, but the client has no terms
    # document of that name configured -> ResourceNotFoundException, a lookup-time absence
    code_no_terms, message_no_terms = _error(
        lambda: cognito.describe_terms_by_client(
            UserPoolId=pool_id, ClientId=client_id, TermsName="terms-of-use"
        )
    )
    assert code_no_terms == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for existing client with no terms, got {code_no_terms}"
    )
    assert message_no_terms == "Terms does not exist.", (
        f"expected message 'Terms does not exist.', got {message_no_terms!r}"
    )
    assert code_bad_name != code_no_terms, (
        "expected the malformed-name and no-terms boundaries to raise distinct error codes, "
        f"both raised {code_bad_name}"
    )

    # positive control: once terms exist for that client, the describe call succeeds
    cognito.create_terms(
        UserPoolId=pool_id,
        ClientId=client_id,
        TermsName="terms-of-use",
        TermsSource="LINK",
        Enforcement="NONE",
        Links={"cognito:default": "https://example.com/terms-of-use"},
    )
    described = cognito.describe_terms_by_client(
        UserPoolId=pool_id, ClientId=client_id, TermsName="terms-of-use"
    )
    assert described["Terms"]["TermsName"] == "terms-of-use", (
        f"expected TermsName 'terms-of-use', got {described['Terms'].get('TermsName')!r}"
    )
    assert described["Terms"]["ClientId"] == client_id, (
        f"expected ClientId {client_id!r}, got {described['Terms'].get('ClientId')!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

