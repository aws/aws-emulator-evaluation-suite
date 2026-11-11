"""merge-developer-identities-self-merge-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "merge-developer-identities-self-merge-rejected"
GROUP = "negative-classes"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """MergeDeveloperIdentities of two distinct developer users unifies them under one identity, and
    a SourceUserIdentifier never linked in the pool is refused with ResourceNotFoundException and
    the exact message without changing the links."""
    cip = ctx.client("cognito-identity")
    dev_provider = ctx.unique_name("sim2real-dev-provider-")
    pool_name = ctx.unique_name("sim2real-behav-cogid-")
    pool_id = cip.create_identity_pool(
        IdentityPoolName=pool_name,
        AllowUnauthenticatedIdentities=False,
        DeveloperProviderName=dev_provider,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: cip.delete_identity_pool(IdentityPoolId=pool_id))

    user_a = "sim2real-user-a"
    user_b = "sim2real-user-b"
    identity_a = cip.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: user_a}
    )["IdentityId"]
    identity_b = cip.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: user_b}
    )["IdentityId"]
    assert identity_a != identity_b, (
        f"two distinct developer logins ({user_a!r}, {user_b!r}) resolved to the same "
        f"IdentityId {identity_a!r} before any merge"
    )

    # Positive control: merging two genuinely distinct developer users succeeds, and
    # after the merge both user identifiers resolve to the very same identity.
    merged_id = cip.merge_developer_identities(
        SourceUserIdentifier=user_b,
        DestinationUserIdentifier=user_a,
        DeveloperProviderName=dev_provider,
        IdentityPoolId=pool_id,
    )["IdentityId"]
    assert merged_id in (identity_a, identity_b), (
        f"merging {user_b!r} into {user_a!r} returned IdentityId {merged_id!r}, expected "
        f"one of the pre-merge identities {identity_a!r} or {identity_b!r}"
    )
    resolved_a_after_merge = cip.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: user_a}
    )["IdentityId"]
    resolved_b_after_merge = cip.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: user_b}
    )["IdentityId"]
    assert resolved_a_after_merge == merged_id, (
        f"after the merge, {user_a!r} resolved to {resolved_a_after_merge!r}, expected the "
        f"merged identity {merged_id!r}"
    )
    assert resolved_b_after_merge == merged_id, (
        f"after the merge, {user_b!r} resolved to {resolved_b_after_merge!r}, expected the "
        f"merged identity {merged_id!r}"
    )

    before_links = set(
        cip.lookup_developer_identity(
            IdentityPoolId=pool_id, IdentityId=merged_id, MaxResults=20
        )["DeveloperUserIdentifierList"]
    )
    assert {user_a, user_b} <= before_links, (
        f"merged identity {merged_id!r} is linked to {before_links!r}, expected it to include "
        f"both {user_a!r} and {user_b!r}"
    )

    # Break exactly one thing: SourceUserIdentifier that was never linked to any
    # identity in this pool.
    ghost_user = "sim2real-user-ghost-does-not-exist"
    code, message = _error(
        lambda: cip.merge_developer_identities(
            SourceUserIdentifier=ghost_user,
            DestinationUserIdentifier=user_a,
            DeveloperProviderName=dev_provider,
            IdentityPoolId=pool_id,
        )
    )
    assert code == "ResourceNotFoundException", (
        f"MergeDeveloperIdentities with an unlinked SourceUserIdentifier {ghost_user!r} "
        f"raised {code!r}, expected ResourceNotFoundException"
    )
    expected_message = f"User '{ghost_user}' not found."
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    # Effect absent: the identity's linked developer identifiers are unchanged.
    after_links = set(
        cip.lookup_developer_identity(
            IdentityPoolId=pool_id, IdentityId=merged_id, MaxResults=20
        )["DeveloperUserIdentifierList"]
    )
    assert after_links == before_links, (
        f"the rejected merge of {ghost_user!r} into {user_a!r} still changed the linked "
        f"identifiers from {before_links!r} to {after_links!r}"
    )


def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
