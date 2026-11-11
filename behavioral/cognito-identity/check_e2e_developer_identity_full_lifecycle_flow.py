"""e2e-developer-identity-full-lifecycle-flow."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-developer-identity-full-lifecycle-flow"
GROUP = "e2e"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A developer identity created via GetOpenIdTokenForDeveloperIdentity is found by
    LookupDeveloperIdentity, merged with a second developer identity, has its login unlinked, and
    DescribeIdentity / DeleteIdentityPool reflect each consequence end-to-end."""
    cognito = ctx.client("cognito-identity")
    dev_provider = ctx.unique_name("sim2real-dev-")

    pool_id = cognito.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_cog_dev_"),
        AllowUnauthenticatedIdentities=False,
        DeveloperProviderName=dev_provider,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    pool_deleted = {"done": False}

    def _cleanup_pool():
        if not pool_deleted["done"]:
            cognito.delete_identity_pool(IdentityPoolId=pool_id)

    ctx.on_cleanup(_cleanup_pool)

    dev_user_1 = ctx.unique_name("sim2real-user1-")
    dev_user_2 = ctx.unique_name("sim2real-user2-")

    identity_1 = cognito.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: dev_user_1}
    )["IdentityId"]

    lookup_1 = cognito.lookup_developer_identity(
        IdentityPoolId=pool_id, DeveloperUserIdentifier=dev_user_1, MaxResults=1
    )
    assert lookup_1["IdentityId"] == identity_1
    assert dev_user_1 in lookup_1["DeveloperUserIdentifierList"]

    identity_2 = cognito.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: dev_user_2}
    )["IdentityId"]
    assert identity_2 != identity_1

    merge = cognito.merge_developer_identities(
        SourceUserIdentifier=dev_user_2,
        DestinationUserIdentifier=dev_user_1,
        DeveloperProviderName=dev_provider,
        IdentityPoolId=pool_id,
    )
    # Per the merge contract, everyone ends up sharing ONE surviving identity — don't assume
    # which of the two pre-merge IDs it is, just that it's one of them.
    merged_id = merge["IdentityId"]
    assert merged_id in (identity_1, identity_2)

    # consequence: both developer users now resolve to the SAME surviving identity.
    resolved_1_after_merge = cognito.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: dev_user_1}
    )["IdentityId"]
    assert resolved_1_after_merge == merged_id

    resolved_after_merge = cognito.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: dev_user_2}
    )["IdentityId"]
    assert resolved_after_merge == merged_id

    lookup_2_after_merge = cognito.lookup_developer_identity(
        IdentityPoolId=pool_id, DeveloperUserIdentifier=dev_user_2, MaxResults=1
    )
    assert lookup_2_after_merge["IdentityId"] == merged_id

    cognito.unlink_developer_identity(
        IdentityId=merged_id,
        IdentityPoolId=pool_id,
        DeveloperProviderName=dev_provider,
        DeveloperUserIdentifier=dev_user_2,
    )

    # Per the contract, an unlinked developer user is "considered a new identity next time
    # they are seen" — so the real consequence is that re-authenticating dev_user_2 now mints
    # a BRAND NEW identity, distinct from the merged one, rather than lookup 404ing outright.
    resolved_after_unlink = _poll_until(
        lambda: cognito.get_open_id_token_for_developer_identity(
            IdentityPoolId=pool_id, Logins={dev_provider: dev_user_2}
        )["IdentityId"],
        lambda iid: iid != merged_id,
        timeout_s=30,
        interval_s=2.0,
        description="dev_user_2 minted as a new identity after unlink",
    )
    assert resolved_after_unlink != merged_id

    lookup_2_after_unlink = cognito.lookup_developer_identity(
        IdentityPoolId=pool_id, DeveloperUserIdentifier=dev_user_2, MaxResults=1
    )
    assert lookup_2_after_unlink["IdentityId"] == resolved_after_unlink

    # positive control: dev_user_1's link (never touched by the unlink) still resolves to the
    # merged identity.
    lookup_1_final = cognito.lookup_developer_identity(
        IdentityPoolId=pool_id, DeveloperUserIdentifier=dev_user_1, MaxResults=1
    )
    assert lookup_1_final["IdentityId"] == merged_id

    desc = cognito.describe_identity(IdentityId=merged_id)
    assert desc["IdentityId"] == merged_id
    assert dev_provider in desc.get("Logins", [])

    cognito.delete_identity_pool(IdentityPoolId=pool_id)
    pool_deleted["done"] = True

    err2_code, err2_message = _client_error(
        lambda: cognito.describe_identity_pool(IdentityPoolId=pool_id), wait_s=60.0
    )
    assert err2_code == "ResourceNotFoundException", (err2_code, err2_message)
    assert err2_message == f"IdentityPool '{pool_id}' not found.", err2_message

    # Not just the pool's own read, but a mutation against the dead pool id
    # also fails -- the deletion is not merely absent from one endpoint.
    mutate_code, mutate_message = _client_error(
        lambda: cognito.lookup_developer_identity(
            IdentityPoolId=pool_id, DeveloperUserIdentifier=dev_user_1, MaxResults=1
        )
    )
    assert mutate_code == "ResourceNotFoundException", (mutate_code, mutate_message)
    assert mutate_message == f"IdentityPool '{pool_id}' not found.", mutate_message


def _client_error(fn, *, wait_s=0.0, interval_s=3.0):
    """Call fn() until it raises a ClientError, for at most ``wait_s``; return (code, message). A
    call that still succeeds at the deadline raises."""
    deadline = time.monotonic() + wait_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")
        time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
