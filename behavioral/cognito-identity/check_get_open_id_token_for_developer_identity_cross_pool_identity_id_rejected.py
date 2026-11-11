"""get-open-id-token-for-developer-identity-cross-pool-identity-id-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-open-id-token-for-developer-identity-cross-pool-identity-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetOpenIdTokenForDeveloperIdentity rejects an explicit IdentityId that belongs to a
    different identity pool, and does not silently link the foreign identity into this pool; a
    fresh call without a foreign IdentityId still succeeds against the same pool."""
    ci = ctx.client("cognito-identity")

    dev_provider_a = ctx.unique_name("sim2real-behav-dev-a-")
    pool_a = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-a-"),
        AllowUnauthenticatedIdentities=False,
        DeveloperProviderName=dev_provider_a,
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool_a_id = pool_a["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_a_id))

    dev_provider_b = ctx.unique_name("sim2real-behav-dev-b-")
    pool_b = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-b-"),
        AllowUnauthenticatedIdentities=False,
        DeveloperProviderName=dev_provider_b,
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool_b_id = pool_b["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_b_id))

    dev_user_a = ctx.unique_name("sim2real-behav-user-a-")
    identity_a = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_a_id, Logins={dev_provider_a: dev_user_a}
    )["IdentityId"]

    dev_user_cross = ctx.unique_name("sim2real-behav-user-cross-")

    def _link_cross_pool_identity():
        return ci.get_open_id_token_for_developer_identity(
            IdentityPoolId=pool_b_id,
            IdentityId=identity_a,
            Logins={dev_provider_b: dev_user_cross},
        )

    code, message = _refusal(_link_cross_pool_identity)
    # Empirically, real AWS rejects an IdentityId that belongs to a foreign identity pool with
    # NotAuthorizedException (the identity is not authorized/owned within pool B's scope), not
    # ResourceNotFoundException.
    assert code == "NotAuthorizedException", (
        f"expected NotAuthorizedException, got {code!r}: {message!r}"
    )
    assert message == f"Access to Identity '{identity_a}' is forbidden.", message

    # Effect absent: the cross-pool developer identifier was never registered against pool B, so
    # LookupDeveloperIdentity for it is refused.
    lookup_code, lookup_message = _refusal(
        lambda: ci.lookup_developer_identity(
            IdentityPoolId=pool_b_id, DeveloperUserIdentifier=dev_user_cross, MaxResults=10
        )
    )
    assert lookup_code == "NotAuthorizedException", (
        f"the rejected cross-pool link nonetheless registered a developer identifier in pool B: "
        f"{lookup_code!r}: {lookup_message!r}"
    )
    assert lookup_message == "You do not have access to this identity", lookup_message

    # Positive control: a normal (same-pool) developer identity call still succeeds against pool B.
    dev_user_ok = ctx.unique_name("sim2real-behav-user-ok-")
    control_identity = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_b_id, Logins={dev_provider_b: dev_user_ok}
    )["IdentityId"]
    assert control_identity, (
        f"expected a real IdentityId from the control call, got {control_identity!r}"
    )

    # Terminal read is independent of the mutating call: LookupDeveloperIdentity, not
    # GetOpenIdTokenForDeveloperIdentity's own response, confirms the control identity is really
    # registered in pool B -- proving the positive control did more than echo an input.
    control_lookup = ci.lookup_developer_identity(
        IdentityPoolId=pool_b_id, DeveloperUserIdentifier=dev_user_ok, MaxResults=1
    )
    assert control_lookup["IdentityId"] == control_identity, (
        f"expected LookupDeveloperIdentity to resolve {dev_user_ok!r} to {control_identity!r} in "
        f"pool B, got {control_lookup['IdentityId']!r}"
    )


def _refusal(fn):
    """Call fn(); return the refusal's (Code, Message). An unexpected success raises, so an
    over-permissive target never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected the call to be refused, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
