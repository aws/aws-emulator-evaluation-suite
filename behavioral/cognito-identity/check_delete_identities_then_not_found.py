"""delete-identities-then-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-identities-then-not-found"
GROUP = "state"
SERVICES = ["cognito-identity"]


def _error(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), status, err.get("Message") or ""
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _list_identity_ids(ci, pool_id):
    """Every IdentityId in ListIdentities for the pool, following NextToken."""
    ids, token = set(), None
    while True:
        kwargs = {"IdentityPoolId": pool_id, "MaxResults": 60}
        if token:
            kwargs["NextToken"] = token
        page = ci.list_identities(**kwargs)
        ids.update(i["IdentityId"] for i in page["Identities"])
        token = page.get("NextToken")
        if not token:
            return ids


def _assert_not_found(label, fn, expected_message):
    """fn() is refused ResourceNotFoundException/400 with the exact message."""
    code, status, message = _error(fn)
    assert code == "ResourceNotFoundException", f"{label}: expected ResourceNotFoundException, got {code!r}: {message!r}"
    assert status == 400, f"{label}: expected HTTP 400, got {status!r}"
    assert message == expected_message, f"{label}: expected the message {expected_message!r}, got {message!r}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteIdentities removes the identities; a subsequent DescribeIdentity on them 404s,
    where DescribeIdentity resolved the same ids immediately beforehand."""
    ci = ctx.client("cognito-identity")
    pool_name = ctx.unique_name("sim2real_pool_").replace("-", "_")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=pool_name,
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id)))

    id_a = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    id_b = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    assert id_a != id_b, f"GetId returned the same identity twice: {id_a}"

    # Positive control: both identities are live and describable before deletion, so the
    # NotFound asserted below proves the delete -- not a target whose DescribeIdentity 404s
    # unconditionally regardless of whether the identity was ever deleted.
    for identity_id in (id_a, id_b):
        described = ci.describe_identity(IdentityId=identity_id)
        assert described["IdentityId"] == identity_id, (
            f"expected DescribeIdentity to resolve {identity_id} before deletion, got {described}"
        )

    listed = _list_identity_ids(ci, pool_id)
    assert {id_a, id_b} <= listed, f"expected ListIdentities to contain both live identities, got {len(listed)} listed"

    resp = ci.delete_identities(IdentityIdsToDelete=[id_a, id_b])
    unprocessed = {u["IdentityId"] for u in resp.get("UnprocessedIdentityIds", [])}
    assert not unprocessed, f"expected both identities processed, unprocessed={unprocessed}"

    # Gone beat 1: the read by id is refused not-found, naming the identity.
    for identity_id in (id_a, id_b):
        _assert_not_found("DescribeIdentity after delete", lambda i=identity_id: ci.describe_identity(IdentityId=i), f"Identity '{identity_id}' not found.")
    # Gone beat 2: the pool's listing no longer contains them.
    listed = _list_identity_ids(ci, pool_id)
    assert not ({id_a, id_b} & listed), "expected ListIdentities to no longer contain the deleted identities"
    # Gone beat 3: a deleted identity is unusable.
    _assert_not_found("GetOpenIdToken on deleted identity", lambda: ci.get_open_id_token(IdentityId=id_a), f"Identity '{id_a}' not found.")

    # The identity pool is deleted and proven gone too.
    ci.delete_identity_pool(IdentityPoolId=pool_id)
    _assert_not_found("DescribeIdentityPool after delete", lambda: ci.describe_identity_pool(IdentityPoolId=pool_id), f"IdentityPool '{pool_id}' not found.")
    pools = [
        p["IdentityPoolId"]
        for page in ci.get_paginator("list_identity_pools").paginate(MaxResults=60)
        for p in page.get("IdentityPools", [])
    ]
    assert pool_id not in pools, f"deleted identity pool {pool_id!r} is still listed by ListIdentityPools"
    _assert_not_found(
        "UpdateIdentityPool after delete",
        lambda: ci.update_identity_pool(
            IdentityPoolId=pool_id, IdentityPoolName=pool_name, AllowUnauthenticatedIdentities=True
        ),
        f"IdentityPool '{pool_id}' not found.",
    )


def _ignore_not_found(fn):
    """Teardown: tolerate only ResourceNotFoundException (the body already deleted it)."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
