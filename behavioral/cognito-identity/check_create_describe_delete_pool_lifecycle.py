"""create-describe-delete-pool-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-describe-delete-pool-lifecycle"
GROUP = 'lifecycle'
SERVICES = ['cognito-identity']

def _error(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), status, err.get("Message") or ""
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _list_pool_ids(ci):
    """Every IdentityPoolId in ListIdentityPools, following NextToken."""
    ids, token = set(), None
    while True:
        kwargs = {"MaxResults": 60}
        if token:
            kwargs["NextToken"] = token
        page = ci.list_identity_pools(**kwargs)
        ids.update(p["IdentityPoolId"] for p in page["IdentityPools"])
        token = page.get("NextToken")
        if not token:
            return ids


def _assert_not_found(ci, label, fn, pool_id):
    """fn() is refused ResourceNotFoundException/4xx with the exact message."""
    code, status, message = _error(fn)
    assert code == "ResourceNotFoundException", f"{label}: expected ResourceNotFoundException, got {code!r}: {message!r}"
    assert isinstance(status, int) and 400 <= status < 500, f"{label}: expected HTTP 4xx, got {status!r}"
    expected_message = f"IdentityPool '{pool_id}' not found."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"


def _delete_pool(ci, pool_id):
    """Teardown that tolerates a pool the check itself already deleted."""
    from botocore.exceptions import ClientError

    try:
        ci.delete_identity_pool(IdentityPoolId=pool_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateIdentityPool -> DescribeIdentityPool reflects config -> DeleteIdentityPool -> gone."""
    ev = ctx.client("cognito-identity")
    name = ctx.unique_name("sim2real-behav-pool-").replace("-", "_")
    resp = ev.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=True,
        AllowClassicFlow=True,
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool_id = resp["IdentityPoolId"]
    ctx.on_cleanup(lambda: _delete_pool(ev, pool_id))
    assert pool_id.startswith(f"{ctx.region}:"), f"expected pool id to start with {ctx.region + ':'!r}, got {pool_id!r}"
    assert resp["IdentityPoolName"] == name, f"expected create response name {name!r}, got {resp['IdentityPoolName']!r}"
    assert resp["AllowUnauthenticatedIdentities"] is True, (
        f"expected create response AllowUnauthenticatedIdentities True, got {resp['AllowUnauthenticatedIdentities']!r}"
    )
    desc = ev.describe_identity_pool(IdentityPoolId=pool_id)
    assert desc["IdentityPoolId"] == pool_id, f"expected describe to echo pool id {pool_id!r}, got {desc['IdentityPoolId']!r}"
    assert desc["IdentityPoolName"] == name, f"expected describe name {name!r}, got {desc['IdentityPoolName']!r}"
    assert desc["AllowUnauthenticatedIdentities"] is True, (
        f"expected describe AllowUnauthenticatedIdentities True, got {desc['AllowUnauthenticatedIdentities']!r}"
    )
    assert desc["AllowClassicFlow"] is True, f"expected describe AllowClassicFlow True, got {desc['AllowClassicFlow']!r}"

    # Use: an update is applied and visible through an independent read.
    ev.update_identity_pool(
        IdentityPoolId=pool_id,
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=False,
        AllowClassicFlow=False,
    )
    updated = ev.describe_identity_pool(IdentityPoolId=pool_id)
    assert updated["AllowUnauthenticatedIdentities"] is False, (
        f"expected AllowUnauthenticatedIdentities False after update, got {updated.get('AllowUnauthenticatedIdentities')!r}"
    )
    assert updated.get("AllowClassicFlow") is False, (
        f"expected AllowClassicFlow False after update, got {updated.get('AllowClassicFlow')!r}"
    )
    listed = _list_pool_ids(ev)
    assert pool_id in listed, f"expected ListIdentityPools to contain the live pool ({len(listed)} pools listed)"

    ev.delete_identity_pool(IdentityPoolId=pool_id)
    # Gone beat 1: the read by id is refused not-found.
    _assert_not_found(ev, "DescribeIdentityPool after delete", lambda: ev.describe_identity_pool(IdentityPoolId=pool_id), pool_id)
    # Gone beat 2: the listing no longer contains it.
    listed = _list_pool_ids(ev)
    assert pool_id not in listed, "expected ListIdentityPools to no longer contain the deleted pool"
    # Gone beat 3: the dead pool is unusable.
    _assert_not_found(
        ev,
        "UpdateIdentityPool on deleted pool",
        lambda: ev.update_identity_pool(
            IdentityPoolId=pool_id, IdentityPoolName=name, AllowUnauthenticatedIdentities=True
        ),
        pool_id,
    )
    _assert_not_found(ev, "GetId on deleted pool", lambda: ev.get_id(IdentityPoolId=pool_id), pool_id)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
