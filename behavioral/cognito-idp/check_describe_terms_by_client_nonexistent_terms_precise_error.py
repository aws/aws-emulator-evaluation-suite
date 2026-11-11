"""describe-terms-by-client-nonexistent-terms-precise-error."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-terms-by-client-nonexistent-terms-precise-error"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTermsByClient fails with ResourceNotFoundException for terms never created and with
    InvalidParameterException for a malformed ClientId, each with its exact message, and returns
    the terms created for the client; the two failure causes must not share one code."""
    idp = ctx.client("cognito-idp")

    pool_id = idp.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-pool-"))["UserPool"][
        "Id"
    ]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-client-")
    )["UserPoolClient"]["ClientId"]

    # Only "privacy-policy" is ever created for this client; "terms-of-use" never is.
    idp.create_terms(
        UserPoolId=pool_id,
        ClientId=client_id,
        TermsName="privacy-policy",
        TermsSource="LINK",
        Enforcement="NONE",
        Links={"cognito:default": "https://example.com/privacy"},
    )
    ctx.on_cleanup(lambda: _delete_terms_by_name(idp, pool_id, client_id, "privacy-policy"))

    # --- Negative 1: valid TermsName, but none created for this client -> ResourceNotFoundException.
    missing_code, missing_message = _error(
        lambda: idp.describe_terms_by_client(
            UserPoolId=pool_id, ClientId=client_id, TermsName="terms-of-use"
        )
    )
    assert missing_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a valid TermsName never created for this "
        f"client, got {missing_code!r}"
    )
    assert missing_message == "Terms does not exist.", (
        f"expected the exact ResourceNotFoundException message 'Terms does not exist.', got {missing_message!r}"
    )

    # --- Negative 2: malformed ClientId -> InvalidParameterException (distinct code).
    malformed_code, malformed_message = _error(
        lambda: idp.describe_terms_by_client(
            UserPoolId=pool_id, ClientId="not a valid client id !!", TermsName="terms-of-use"
        )
    )
    assert malformed_code == "InvalidParameterException", (
        f"expected InvalidParameterException for a malformed ClientId, got {malformed_code!r}"
    )
    expected_malformed = (
        "1 validation error detected: Value 'not a valid client id !!' at 'clientId' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: [\\w+]+"
    )
    assert malformed_message == expected_malformed, (
        f"expected the exact InvalidParameterException message {expected_malformed!r}, got {malformed_message!r}"
    )
    assert malformed_code != missing_code, (
        "expected the malformed-ClientId and no-terms-for-client boundaries to raise distinct "
        f"error codes, both raised {malformed_code!r}"
    )

    # --- Positive control: describing the terms that *were* created succeeds.
    resp = idp.describe_terms_by_client(
        UserPoolId=pool_id, ClientId=client_id, TermsName="privacy-policy"
    )
    assert resp["Terms"]["TermsName"] == "privacy-policy", (
        f"expected TermsName 'privacy-policy', got {resp['Terms'].get('TermsName')!r}"
    )
    assert resp["Terms"]["ClientId"] == client_id, (
        f"expected ClientId {client_id!r}, got {resp['Terms'].get('ClientId')!r}"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because a target that accepts a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_terms_by_name(idp, pool_id: str, client_id: str, terms_name: str) -> None:
    try:
        terms_id = idp.describe_terms_by_client(
            UserPoolId=pool_id, ClientId=client_id, TermsName=terms_name
        )["Terms"]["TermsId"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    idp.delete_terms(UserPoolId=pool_id, TermsId=terms_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
