"""describe-terms-by-client-mismatched-client-id-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-terms-by-client-mismatched-client-id-rejected"
GROUP = "negative-classes"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeTermsByClient rejects a ClientId that belongs to a different user pool
    than the terms resource, instead of leaking that pool's terms data."""
    cognito = ctx.client("cognito-idp")

    pool_tags = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
    pool_a = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-termsA-"), UserPoolTags=pool_tags
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_a))
    pool_b = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-termsB-"), UserPoolTags=pool_tags
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_b))

    client_a = cognito.create_user_pool_client(
        UserPoolId=pool_a, ClientName=ctx.unique_name("sim2real-clientA-")
    )["UserPoolClient"]["ClientId"]
    client_b = cognito.create_user_pool_client(
        UserPoolId=pool_b, ClientName=ctx.unique_name("sim2real-clientB-")
    )["UserPoolClient"]["ClientId"]

    cognito.create_terms(
        UserPoolId=pool_a,
        ClientId=client_a,
        TermsName="terms-of-use",
        TermsSource="LINK",
        Enforcement="NONE",
        Links={"cognito:default": "https://example.com/terms"},
    )

    # client_b is a real app client, but it belongs to pool_b, not pool_a
    code, message = _error(
        lambda: cognito.describe_terms_by_client(
            UserPoolId=pool_a, ClientId=client_b, TermsName="terms-of-use"
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = f"User pool client {client_b} does not exist in user pool {pool_a}."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: exactly one terms document exists in pool A, unaffected by the bad lookup
    terms_list = cognito.list_terms(UserPoolId=pool_a)["Terms"]
    assert len(terms_list) == 1 and terms_list[0]["TermsName"] == "terms-of-use", (
        f"expected exactly one untouched terms document in pool_a, got {terms_list!r}"
    )

    # positive control: the matching pool/client/terms-name combination succeeds
    resp = cognito.describe_terms_by_client(
        UserPoolId=pool_a, ClientId=client_a, TermsName="terms-of-use"
    )
    assert resp["Terms"]["TermsName"] == "terms-of-use", (
        f"expected TermsName terms-of-use, got {resp['Terms'].get('TermsName')!r}"
    )
    assert resp["Terms"]["ClientId"] == client_a, (
        f"expected ClientId {client_a}, got {resp['Terms'].get('ClientId')!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
