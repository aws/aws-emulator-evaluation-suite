"""delete-nonexistent-terms-fails."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "delete-nonexistent-terms-fails"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTerms with a malformed TermsId is refused with InvalidParameterException and the exact
    validation message; deleting real terms removes them, after which DescribeTerms and a second
    DeleteTerms answer ResourceNotFoundException with the exact message."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)
    client_id = _create_client(ctx, pool_id)

    # Negative: a TermsId that was never created.
    bogus_terms_id = "00000000-0000-0000-0000-000000000000"
    code, message = _error(lambda: idp.delete_terms(TermsId=bogus_terms_id, UserPoolId=pool_id))
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert message == (
        f"1 validation error detected: Value '{bogus_terms_id}' at 'termsId' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: "
        "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[4][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
    ), f"unexpected message {message!r}"

    # Positive control: create real Terms, confirm it describes, delete it, confirm it's gone.
    created = idp.create_terms(
        UserPoolId=pool_id,
        ClientId=client_id,
        TermsName="terms-of-use",
        TermsSource="LINK",
        Enforcement="NONE",
        Links={"cognito:default": "https://terms.example.com/tos"},
    )
    terms_id = created["Terms"]["TermsId"]

    described = idp.describe_terms(TermsId=terms_id, UserPoolId=pool_id)
    assert described["Terms"]["TermsId"] == terms_id, (
        f"expected describe_terms to echo TermsId {terms_id!r}, got {described['Terms']!r}"
    )

    idp.delete_terms(TermsId=terms_id, UserPoolId=pool_id)

    code_after_delete, message_after_delete = _error(
        lambda: idp.describe_terms(TermsId=terms_id, UserPoolId=pool_id)
    )
    assert code_after_delete == "ResourceNotFoundException", (
        f"terms should be gone after delete, got {code_after_delete}"
    )
    assert message_after_delete == "Terms does not exist.", (
        f"DescribeTerms after delete: message {message_after_delete!r}"
    )

    # A mutation on the now-dead id must also fail, not silently succeed a second time.
    code_double_delete, message_double_delete = _error(
        lambda: idp.delete_terms(TermsId=terms_id, UserPoolId=pool_id)
    )
    assert code_double_delete == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException on double-delete, got {code_double_delete}"
    )
    assert message_double_delete == "Terms does not exist.", (
        f"DeleteTerms on the deleted id: message {message_double_delete!r}"
    )


def _create_pool(ctx) -> str:
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
        DeletionProtection="INACTIVE",
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_client(ctx, pool_id: str) -> str:
    idp = ctx.client("cognito-idp")
    resp = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )
    client_id = resp["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: idp.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))
    return client_id


def _error(fn) -> Any:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to fail, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
