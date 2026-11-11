"""e2e-identity-population-delete-merge-unlink-final-state."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-identity-population-delete-merge-unlink-final-state"
GROUP = "e2e"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteIdentities, MergeDeveloperIdentities and UnlinkDeveloperIdentity leave exactly the
    surviving identity population their documented semantics predict, observed via
    DescribeIdentity/LookupDeveloperIdentity/ListIdentities as the consequence of each call."""
    cognito = ctx.client("cognito-identity")
    dev_provider = ctx.unique_name("sim2real-behav-dp-")
    pool_name = ctx.unique_name("sim2real-behav-pool-")
    pool_id = cognito.create_identity_pool(
        IdentityPoolName=pool_name,
        AllowUnauthenticatedIdentities=True,
        DeveloperProviderName=dev_provider,
        IdentityPoolTags={"sim2real": "behavioral-audit"},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: cognito.delete_identity_pool(IdentityPoolId=pool_id))

    id_to_delete = cognito.get_id(IdentityPoolId=pool_id)["IdentityId"]
    id_to_keep = cognito.get_id(IdentityPoolId=pool_id)["IdentityId"]
    assert id_to_delete != id_to_keep

    src_user = ctx.unique_name("dev-src-")
    dst_user = ctx.unique_name("dev-dst-")
    id_src = cognito.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: src_user}
    )["IdentityId"]
    id_dst = cognito.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: dst_user}
    )["IdentityId"]
    assert id_src != id_dst

    created_ids = {id_to_delete, id_to_keep, id_src, id_dst}
    listed = cognito.list_identities(IdentityPoolId=pool_id, MaxResults=60, HideDisabled=True)
    listed_ids = {i["IdentityId"] for i in listed["Identities"]}
    assert created_ids <= listed_ids

    unprocessed = cognito.delete_identities(IdentityIdsToDelete=[id_to_delete])["UnprocessedIdentityIds"]
    assert unprocessed == []
    err = _client_error(lambda: cognito.describe_identity(IdentityId=id_to_delete))
    assert err == ("ResourceNotFoundException", f"Identity '{id_to_delete}' not found."), err

    merge_resp = cognito.merge_developer_identities(
        SourceUserIdentifier=src_user,
        DestinationUserIdentifier=dst_user,
        DeveloperProviderName=dev_provider,
        IdentityPoolId=pool_id,
    )
    # The API contract only guarantees ONE of the two pre-merge identities survives, carrying
    # both developer logins; it does not fix which of {source, destination} IdentityId that is
    # empirically it may not be the DestinationUserIdentifier's IdentityId, so verify the
    # invariant defensively rather than assuming the destination survives.
    survivor_id = merge_resp["IdentityId"]
    assert survivor_id in (id_src, id_dst), survivor_id
    absorbed_id = id_src if survivor_id == id_dst else id_dst
    # Empirically, the absorbed identity record is NOT deleted by the merge -- only its developer
    # login is moved onto the survivor. DescribeIdentity on it still succeeds, but it no longer
    # carries any developer login (that moved to survivor_id).
    absorbed_identity = cognito.describe_identity(IdentityId=absorbed_id)
    assert absorbed_identity["IdentityId"] == absorbed_id

    lookup_before = cognito.lookup_developer_identity(
        IdentityPoolId=pool_id, IdentityId=survivor_id, MaxResults=10
    )
    assert set(lookup_before["DeveloperUserIdentifierList"]) == {src_user, dst_user}
    # LookupDeveloperIdentity on the absorbed identity is empirically rejected once it carries no
    # developer login at all ("You do not have access to this identity") -- it is no longer a
    # developer identity from Cognito's perspective, so this negative control also serves as the
    # overly-permissive boundary check: absorbed_id must NOT be addressable via this API anymore.
    absorbed_lookup_err = _client_error(
        lambda: cognito.lookup_developer_identity(
            IdentityPoolId=pool_id, IdentityId=absorbed_id, MaxResults=10
        )
    )
    assert absorbed_lookup_err == ("NotAuthorizedException", "You do not have access to this identity"), absorbed_lookup_err


    cognito.unlink_developer_identity(
        IdentityId=survivor_id,
        IdentityPoolId=pool_id,
        DeveloperProviderName=dev_provider,
        DeveloperUserIdentifier=dst_user,
    )
    lookup_after = cognito.lookup_developer_identity(
        IdentityPoolId=pool_id, IdentityId=survivor_id, MaxResults=10
    )
    assert set(lookup_after["DeveloperUserIdentifierList"]) == {src_user}

    # survivor_id persists: dst_user was not its only login (src_user remains linked to it).
    cognito.describe_identity(IdentityId=survivor_id)

    # Final population: id_to_delete was truly removed by DeleteIdentities. The absorbed identity
    # is empirically disabled by the merge (it is hidden from the default HideDisabled=True view,
    # though it still exists -- DescribeIdentity above still resolves it).
    final_listed = cognito.list_identities(IdentityPoolId=pool_id, MaxResults=60, HideDisabled=True)
    final_ids = {i["IdentityId"] for i in final_listed["Identities"]} & created_ids
    assert final_ids == {id_to_keep, survivor_id}
    assert id_to_delete not in final_ids
    assert absorbed_id not in final_ids

    all_listed = cognito.list_identities(IdentityPoolId=pool_id, MaxResults=60, HideDisabled=False)
    all_ids = {i["IdentityId"] for i in all_listed["Identities"]} & created_ids
    assert absorbed_id in all_ids
    assert id_to_delete not in all_ids


def _client_error(fn):
    """Call fn(); return the ClientError's (code, message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
