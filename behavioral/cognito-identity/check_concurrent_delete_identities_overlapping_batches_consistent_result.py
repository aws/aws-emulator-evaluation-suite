"""concurrent-delete-identities-overlapping-batches-consistent-result."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-delete-identities-overlapping-batches-consistent-result"
GROUP = "concurrency"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent DeleteIdentities calls with overlapping batches both report no unprocessed ids, and every
    identity in either batch then fails DescribeIdentity with ResourceNotFoundException and its exact message.
    """
    cid = ctx.client("cognito-identity")
    pool = cid.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool_id = pool["IdentityPoolId"]
    ctx.on_cleanup(lambda: cid.delete_identity_pool(IdentityPoolId=pool_id))

    identity_ids = [cid.get_id(IdentityPoolId=pool_id)["IdentityId"] for _ in range(4)]
    assert len(set(identity_ids)) == 4, "expected 4 distinct unauthenticated identities"

    batch1 = [identity_ids[0], identity_ids[1], identity_ids[2]]
    batch2 = [identity_ids[1], identity_ids[2], identity_ids[3]]

    with ThreadPoolExecutor(max_workers=2) as pool_exec:
        f1 = pool_exec.submit(cid.delete_identities, IdentityIdsToDelete=batch1)
        f2 = pool_exec.submit(cid.delete_identities, IdentityIdsToDelete=batch2)
        resp1 = f1.result()
        resp2 = f2.result()

    assert resp1.get("UnprocessedIdentityIds", []) == [], resp1.get("UnprocessedIdentityIds")
    assert resp2.get("UnprocessedIdentityIds", []) == [], resp2.get("UnprocessedIdentityIds")

    for iid in identity_ids:
        code, message = _error(lambda iid=iid: cid.describe_identity(IdentityId=iid))
        assert code == "ResourceNotFoundException", f"{iid} still describable after delete: {code}"
        expected = f"Identity '{iid}' not found."
        assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
