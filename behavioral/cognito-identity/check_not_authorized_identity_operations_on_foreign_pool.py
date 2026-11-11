"""not-authorized-identity-operations-on-foreign-pool."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "not-authorized-identity-operations-on-foreign-pool"
GROUP = 'overly-permissive'
SERVICES = ['cognito-identity']

def _error(fn):
    """Call fn(); return the ClientError's (Code, Message). An unexpected success raises with the
    returned payload, so it never reads as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListIdentities, LookupDeveloperIdentity, MergeDeveloperIdentities and UnlinkDeveloperIdentity
    raise ResourceNotFoundException for a nonexistent identity pool, while each succeeds on a real
    pool, so the refusal is specific to the unknown pool."""
    ev = ctx.client("cognito-identity")

    dev_provider = ctx.unique_name("sim2real-dev-")
    pool_id = ev.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_behav_"),
        AllowUnauthenticatedIdentities=True,
        DeveloperProviderName=dev_provider,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ev.delete_identity_pool(IdentityPoolId=pool_id))

    list_user = ctx.unique_name("user-list-")
    list_identity_id = ev.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: list_user}
    )["IdentityId"]
    ctx.on_cleanup(lambda: ev.delete_identities(IdentityIdsToDelete=[list_identity_id]))

    source_user = ctx.unique_name("user-src-")
    dest_user = ctx.unique_name("user-dst-")
    source_identity_id = ev.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: source_user}
    )["IdentityId"]
    dest_identity_id = ev.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: dest_user}
    )["IdentityId"]
    ctx.on_cleanup(lambda: ev.delete_identities(IdentityIdsToDelete=[dest_identity_id]))

    unlink_user = ctx.unique_name("user-unlink-")
    unlink_identity_id = ev.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: unlink_user}
    )["IdentityId"]
    ctx.on_cleanup(lambda: ev.delete_identities(IdentityIdsToDelete=[unlink_identity_id]))

    foreign_pool_id = f"{ctx.region}:{uuid.uuid4()}"
    pool_not_found = f"IdentityPool '{foreign_pool_id}' not found."

    listed = ev.list_identities(IdentityPoolId=pool_id, MaxResults=5)
    assert any(i["IdentityId"] == list_identity_id for i in listed.get("Identities", [])), (
        f"expected {list_identity_id} in ListIdentities on the real pool, got {listed.get('Identities')}"
    )
    code, message = _error(
        lambda: ev.list_identities(IdentityPoolId=foreign_pool_id, MaxResults=5)
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for ListIdentities on a nonexistent pool, got {code}"
    )
    assert message == pool_not_found, (
        f"ListIdentities: expected message {pool_not_found!r}, got {message!r}"
    )

    looked_up = ev.lookup_developer_identity(
        IdentityPoolId=pool_id, DeveloperUserIdentifier=list_user, MaxResults=1
    )
    assert looked_up["IdentityId"] == list_identity_id, (
        f"expected LookupDeveloperIdentity on the real pool to resolve {list_user!r} to "
        f"{list_identity_id}, got {looked_up['IdentityId']}"
    )
    code, message = _error(
        lambda: ev.lookup_developer_identity(
            IdentityPoolId=foreign_pool_id, DeveloperUserIdentifier="nobody", MaxResults=1
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for LookupDeveloperIdentity on a nonexistent pool, got {code}"
    )
    assert message == pool_not_found, (
        f"LookupDeveloperIdentity: expected message {pool_not_found!r}, got {message!r}"
    )

    merge_resp = ev.merge_developer_identities(
        SourceUserIdentifier=source_user,
        DestinationUserIdentifier=dest_user,
        DeveloperProviderName=dev_provider,
        IdentityPoolId=pool_id,
    )
    assert merge_resp["IdentityId"] in (source_identity_id, dest_identity_id), (
        f"expected MergeDeveloperIdentities on the real pool to retain one of the two input "
        f"identities, got {merge_resp['IdentityId']}"
    )
    merged_lookup = ev.lookup_developer_identity(
        IdentityPoolId=pool_id, DeveloperUserIdentifier=dest_user, MaxResults=1
    )
    assert merged_lookup["IdentityId"] == merge_resp["IdentityId"], (
        f"expected an independent LookupDeveloperIdentity on the real pool to resolve {dest_user!r} "
        f"to the post-merge survivor {merge_resp['IdentityId']}, got {merged_lookup['IdentityId']}"
    )
    code, message = _error(
        lambda: ev.merge_developer_identities(
            SourceUserIdentifier="source-user",
            DestinationUserIdentifier="dest-user",
            DeveloperProviderName="some.dev.provider",
            IdentityPoolId=foreign_pool_id,
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for MergeDeveloperIdentities on a nonexistent pool, got {code}"
    )
    assert message == pool_not_found, (
        f"MergeDeveloperIdentities: expected message {pool_not_found!r}, got {message!r}"
    )

    ev.unlink_developer_identity(
        IdentityId=unlink_identity_id,
        IdentityPoolId=pool_id,
        DeveloperProviderName=dev_provider,
        DeveloperUserIdentifier=unlink_user,
    )
    described = ev.describe_identity(IdentityId=unlink_identity_id)
    assert dev_provider not in described.get("Logins", []), (
        f"expected UnlinkDeveloperIdentity on the real pool to remove {dev_provider!r} from "
        f"{unlink_identity_id}'s Logins, got {described.get('Logins')}"
    )

    fake_identity_id = f"{ctx.region}:{uuid.uuid4()}"
    code, message = _error(
        lambda: ev.unlink_developer_identity(
            IdentityId=fake_identity_id,
            IdentityPoolId=foreign_pool_id,
            DeveloperProviderName="some.dev.provider",
            DeveloperUserIdentifier="nobody",
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for UnlinkDeveloperIdentity on a nonexistent pool, got {code}"
    )
    # UnlinkDeveloperIdentity names the unknown identity, not the pool.
    expected_message = f"Identity '{fake_identity_id}' not found."
    assert message == expected_message, (
        f"UnlinkDeveloperIdentity: expected message {expected_message!r}, got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
