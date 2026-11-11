"""list-identities-hide-disabled-after-merge."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-identities-hide-disabled-after-merge"
GROUP = "state"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After MergeDeveloperIdentities disables the destination identity, ListIdentities with
    HideDisabled=True omits it and keeps the surviving source identity, while the default listing
    includes both."""
    ci = ctx.client("cognito-identity")
    dev_provider = "login.sim2real.hidedisabled"
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_pool_").replace("-", "_"),
        AllowUnauthenticatedIdentities=True,
        DeveloperProviderName=dev_provider,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    src_user = ctx.unique_name("user-hd-src-")
    dst_user = ctx.unique_name("user-hd-dst-")
    src_identity = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: src_user}
    )["IdentityId"]
    dst_identity = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: dst_user}
    )["IdentityId"]

    ci.merge_developer_identities(
        SourceUserIdentifier=src_user,
        DestinationUserIdentifier=dst_user,
        DeveloperProviderName=dev_provider,
        IdentityPoolId=pool_id,
    )

    # The disable resulting from the merge is eventually consistent in ListIdentities, so poll a
    # bounded number of times rather than asserting on the very first listing.
    hidden_ids = _poll_until_excluded(ci, pool_id, dst_identity)
    assert dst_identity not in hidden_ids, (
        "merged-away (disabled) destination identity should not appear when HideDisabled=True"
    )
    assert src_identity in hidden_ids, "surviving source identity missing from HideDisabled=True listing"

    default_ids = _list_all(ci, pool_id, hide_disabled=None)
    assert dst_identity in default_ids, (
        "disabled destination identity should still appear when HideDisabled is omitted (default includes disabled)"
    )
    assert src_identity in default_ids, "surviving source identity missing from HideDisabled-omitted listing"


def _poll_until_excluded(ci, pool_id: str, identity_id: str, *, timeout_s=20.0, interval_s=2.0) -> set[str]:
    deadline = time.monotonic() + timeout_s
    ids = _list_all(ci, pool_id, hide_disabled=True)
    while identity_id in ids and time.monotonic() < deadline:
        time.sleep(interval_s)
        ids = _list_all(ci, pool_id, hide_disabled=True)
    return ids


def _list_all(ci, pool_id: str, hide_disabled) -> set[str]:
    ids: set[str] = set()
    next_token = None
    pages = 0
    while True:
        kwargs = {"IdentityPoolId": pool_id, "MaxResults": 60}
        if hide_disabled is not None:
            kwargs["HideDisabled"] = hide_disabled
        if next_token:
            kwargs["NextToken"] = next_token
        resp = ci.list_identities(**kwargs)
        ids.update(i["IdentityId"] for i in resp.get("Identities", []))
        next_token = resp.get("NextToken")
        pages += 1
        if not next_token or pages > 20:
            break
    return ids


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

