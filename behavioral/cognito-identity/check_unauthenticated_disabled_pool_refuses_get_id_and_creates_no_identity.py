"""unauthenticated-disabled-pool-refuses-get-id-and-creates-no-identity."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unauthenticated-disabled-pool-refuses-get-id-and-creates-no-identity"
GROUP = 'overly-permissive'
SERVICES = ['cognito-identity']

EXPECTED_CODE = "NotAuthorizedException"
EXPECTED_MESSAGE = "Unauthenticated access is not supported for this identity pool."


def _refusal(fn):
    """Call fn(); return (Code, Message) if refused. A call that must be refused and was not
    raises, so it never reads as a missing code."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _list_identities(ci, pool_id):
    """Every identity in the pool, paginated — the assertions below are set differences."""
    ids = set()
    next_token = None
    pages = 0
    while True:
        kwargs = {"IdentityPoolId": pool_id, "MaxResults": 60}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = ci.list_identities(**kwargs)
        ids.update(i["IdentityId"] for i in resp.get("Identities", []))
        next_token = resp.get("NextToken")
        pages += 1
        if not next_token or pages > 50:
            return ids


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """With AllowUnauthenticatedIdentities=False a Logins-less GetId is refused and creates no
    identity, a developer login on the same pool creates one, and enabling the flag lets GetId work.
    """
    ci = ctx.client("cognito-identity")
    developer_provider = ctx.unique_name("sim2real-behav-noguest-dev-")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_behav_noguest_").replace("-", "_"),
        AllowUnauthenticatedIdentities=False,
        DeveloperProviderName=developer_provider,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    described = ci.describe_identity_pool(IdentityPoolId=pool_id)
    assert described["AllowUnauthenticatedIdentities"] is False, (
        f"the pool was created with unauthenticated identities disabled, DescribeIdentityPool "
        f"reports {described['AllowUnauthenticatedIdentities']!r}"
    )

    ids_before = _list_identities(ci, pool_id)

    # ---- the one thing under test: an anonymous GetId
    code, message = _refusal(lambda: ci.get_id(IdentityPoolId=pool_id))
    assert code == EXPECTED_CODE, (
        f"expected {EXPECTED_CODE!r} with unauthenticated identities disabled, got {code!r}: "
        f"{message!r}"
    )
    assert message == EXPECTED_MESSAGE, (
        f"expected the refusal message {EXPECTED_MESSAGE!r}, got {message!r}"
    )

    # ---- the effect is absent: nothing was allocated for the refused call
    ids_after_reject = _list_identities(ci, pool_id)
    assert ids_after_reject == ids_before, (
        f"an identity appeared for a rejected GetId: "
        f"{sorted(ids_after_reject - ids_before)!r}"
    )

    # ---- positive control 1: the authenticated path on the same pool does create one
    developer_user_id = ctx.unique_name("sim2real-behav-noguest-user-")
    login_identity_id = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={developer_provider: developer_user_id}
    )["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[login_identity_id]))
    ids_after_login = _list_identities(ci, pool_id)
    assert ids_after_login - ids_before == {login_identity_id}, (
        f"the developer login should have created exactly {login_identity_id!r}, the pool gained "
        f"{sorted(ids_after_login - ids_before)!r}"
    )

    # ---- positive control 2: flipping the flag makes the previously-refused call succeed
    ci.update_identity_pool(
        IdentityPoolId=pool_id,
        IdentityPoolName=described["IdentityPoolName"],
        AllowUnauthenticatedIdentities=True,
        DeveloperProviderName=developer_provider,
    )
    # No retry: GetId succeeds immediately after UpdateIdentityPool enables the flag.
    flipped_identity_id = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[flipped_identity_id]))
    assert flipped_identity_id not in ids_after_login, (
        f"GetId after enabling unauthenticated identities returned the pre-existing identity "
        f"{flipped_identity_id!r} instead of allocating one"
    )

    # ---- terminal read: independent of GetId's own response, at the destination
    ids_after_flip = _list_identities(ci, pool_id)
    assert ids_after_flip - ids_after_login == {flipped_identity_id}, (
        f"ListIdentities should show exactly the newly allocated {flipped_identity_id!r} after the "
        f"flip, the pool instead gained {sorted(ids_after_flip - ids_after_login)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
