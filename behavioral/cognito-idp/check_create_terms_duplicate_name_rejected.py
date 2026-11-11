"""create-terms-duplicate-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-terms-duplicate-name-rejected"
GROUP = "server-side"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTerms with a TermsName the client already has is refused with TermsExistsException and
    the exact message and leaves the original unchanged; another TermsName is created, and after
    deleting the original the name can be reused."""
    idp = ctx.client("cognito-idp")

    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-terms-dup-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-terms-dup"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-terms-dup-client-")
    )["UserPoolClient"]["ClientId"]

    original = idp.create_terms(
        UserPoolId=pool_id,
        ClientId=client_id,
        TermsName="terms-of-use",
        TermsSource="LINK",
        Enforcement="NONE",
        Links={"cognito:default": "https://original.example.com/terms"},
    )["Terms"]

    code, message = _error(
        lambda: idp.create_terms(
            UserPoolId=pool_id,
            ClientId=client_id,
            TermsName="terms-of-use",
            TermsSource="LINK",
            Enforcement="NONE",
            Links={"cognito:default": "https://overwrite.example.com/terms"},
        )
    )
    assert code == "TermsExistsException", f"expected TermsExistsException, got {code}"
    expected_message = f"Terms with name terms-of-use already exists for Client {client_id}."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the original terms document is untouched by the rejected request.
    current = idp.describe_terms_by_client(
        UserPoolId=pool_id, ClientId=client_id, TermsName="terms-of-use"
    )["Terms"]
    assert current["TermsId"] == original["TermsId"], (
        f"expected TermsId {original['TermsId']!r} unchanged, got {current['TermsId']!r}"
    )
    assert current["Links"] == {"cognito:default": "https://original.example.com/terms"}, (
        f"expected original Links preserved, got {current['Links']!r}"
    )

    # Positive control: a different TermsName for the same client still succeeds, so the
    # rejection above is scoped to the duplicate name and not a blanket CreateTerms failure.
    idp.create_terms(
        UserPoolId=pool_id,
        ClientId=client_id,
        TermsName="privacy-policy",
        TermsSource="LINK",
        Enforcement="NONE",
        Links={"cognito:default": "https://original.example.com/privacy"},
    )
    privacy = idp.describe_terms_by_client(
        UserPoolId=pool_id, ClientId=client_id, TermsName="privacy-policy"
    )["Terms"]
    assert privacy["Links"] == {"cognito:default": "https://original.example.com/privacy"}, (
        f"expected the positive-control document's own Links, got {privacy['Links']!r}"
    )

    # Restore leg: this is a uniqueness conflict, not a permanently invalid TermsName —
    # deleting the original document must free the name for reuse.
    idp.delete_terms(UserPoolId=pool_id, TermsId=original["TermsId"])
    idp.create_terms(
        UserPoolId=pool_id,
        ClientId=client_id,
        TermsName="terms-of-use",
        TermsSource="LINK",
        Enforcement="NONE",
        Links={"cognito:default": "https://restored.example.com/terms"},
    )
    restored = idp.describe_terms_by_client(
        UserPoolId=pool_id, ClientId=client_id, TermsName="terms-of-use"
    )["Terms"]
    assert restored["TermsId"] != original["TermsId"], (
        f"expected a fresh TermsId after delete+recreate, got the original {original['TermsId']!r} again"
    )
    assert restored["Links"] == {"cognito:default": "https://restored.example.com/terms"}, (
        f"expected the restore leg's own Links to have landed, got {restored['Links']!r}"
    )


def _error(fn):
    """The (code, message) a call raised. Raises if the call SUCCEEDS."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection but the call SUCCEEDED, returning {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
