"""terms-duplicate-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "terms-duplicate-name-rejected"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating terms with a TermsName that already exists for the client is rejected."""
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-pool-"))["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-client-")
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))

    created = cognito.create_terms(
        UserPoolId=pool_id,
        ClientId=client_id,
        TermsName="privacy-policy",
        TermsSource="LINK",
        Enforcement="NONE",
        Links={"cognito:default": "https://sim2real-behav.example.com/privacy"},
    )["Terms"]
    terms_id = created["TermsId"]
    ctx.on_cleanup(
        lambda: _ignore_errors(lambda: cognito.delete_terms(UserPoolId=pool_id, TermsId=terms_id))
    )

    code, message = _error(
        lambda: cognito.create_terms(
            UserPoolId=pool_id,
            ClientId=client_id,
            TermsName="privacy-policy",
            TermsSource="LINK",
            Enforcement="NONE",
            Links={"cognito:default": "https://sim2real-behav.example.com/privacy-dup"},
        )
    )
    assert code == "TermsExistsException", f"expected TermsExistsException, got {code}"
    expected_message = f"Terms with name privacy-policy already exists for Client {client_id}."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # the original terms document must remain untouched by the rejected duplicate attempt
    still = cognito.describe_terms(UserPoolId=pool_id, TermsId=terms_id)["Terms"]
    assert still["TermsId"] == terms_id, f"expected unchanged TermsId {terms_id}, got {still['TermsId']}"
    assert still["Links"]["cognito:default"] == "https://sim2real-behav.example.com/privacy", (
        f"expected original link untouched, got {still['Links']}"
    )

    # positive control: create_terms still works for the same client under the other allowed
    # TermsName, ruling out "everything is now rejected" as an explanation for the exception above.
    # TermsName is a closed enum (terms-of-use|privacy-policy) enforced by CreateTerms itself.
    other = cognito.create_terms(
        UserPoolId=pool_id,
        ClientId=client_id,
        TermsName="terms-of-use",
        TermsSource="LINK",
        Enforcement="NONE",
        Links={"cognito:default": "https://sim2real-behav.example.com/tou"},
    )["Terms"]
    ctx.on_cleanup(
        lambda: _ignore_errors(
            lambda: cognito.delete_terms(UserPoolId=pool_id, TermsId=other["TermsId"])
        )
    )
    assert other["TermsName"] == "terms-of-use", f"expected terms-of-use, got {other['TermsName']}"


def _ignore_errors(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
