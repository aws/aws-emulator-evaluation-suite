"""create-terms-foreign-client-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-terms-foreign-client-rejected"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTerms with a ClientId from another user pool is refused with ResourceNotFoundException
    and the exact message, while the same call with the pool's own client creates the terms that
    ListTerms returns."""
    idp = ctx.client("cognito-idp")

    tags = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
    pool_a = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-a-"), UserPoolTags=tags
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_a))
    pool_b = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-b-"), UserPoolTags=tags
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_b))

    client_a = idp.create_user_pool_client(
        UserPoolId=pool_a, ClientName=ctx.unique_name("sim2real-client-a-")
    )["UserPoolClient"]["ClientId"]
    client_b = idp.create_user_pool_client(
        UserPoolId=pool_b, ClientName=ctx.unique_name("sim2real-client-b-")
    )["UserPoolClient"]["ClientId"]

    # Positive control: client_a genuinely belongs to pool_a, so the identical shape of
    # call succeeds. Without this, "rejects a foreign client" is indistinguishable from
    # "rejects every CreateTerms call".
    created = idp.create_terms(
        UserPoolId=pool_a,
        ClientId=client_a,
        TermsName="terms-of-use",
        TermsSource="LINK",
        Enforcement="NONE",
        Links={"cognito:default": "https://terms.example.com/tou"},
    )["Terms"]
    assert created["ClientId"] == client_a, (
        f"positive control: expected the created terms to be scoped to {client_a!r}, "
        f"got {created.get('ClientId')!r}"
    )

    # Break exactly one thing: name a ClientId from pool_b while still asking pool_a.
    code, message = _error(
        lambda: idp.create_terms(
            UserPoolId=pool_a,
            ClientId=client_b,
            TermsName="privacy-policy",
            TermsSource="LINK",
            Enforcement="NONE",
            Links={"cognito:default": "https://terms.example.com/privacy"},
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = f"User pool client {client_b} does not exist in user pool {pool_a}."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: pool_a still has exactly the one terms document the positive
    # control created -- the rejected cross-pool request left no trace.
    listed = idp.list_terms(UserPoolId=pool_a)["Terms"]
    assert [t["TermsName"] for t in listed] == ["terms-of-use"], (
        f"expected only the positive control's terms-of-use document in pool_a, got "
        f"{[t.get('TermsName') for t in listed]!r}"
    )


def _error(fn):
    """The AWS error code and message a call raised. Raises if the call SUCCEEDS."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection but the call SUCCEEDED, returning {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
