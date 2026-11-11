"""delete-identities-unprocessed-order-matches-input."""
from __future__ import annotations

import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-identities-unprocessed-order-matches-input"
GROUP = "ordering"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteIdentities on real identity ids interleaved with never-issued ones returns an empty
    UnprocessedIdentityIds and deletes every real id: DescribeIdentity then answers
    ResourceNotFoundException with the exact message."""
    client = ctx.client("cognito-identity")
    pool_id = _create_pool(ctx, client)

    real_ids = [client.get_id(IdentityPoolId=pool_id)["IdentityId"] for _ in range(3)]
    region = pool_id.split(":")[0]
    fake_ids = [f"{region}:{uuid.uuid4()}" for _ in range(2)]

    # interleave real and fake ids so a real id sits both before and after a fake one
    ids_to_delete = [real_ids[0], fake_ids[0], real_ids[1], fake_ids[1], real_ids[2]]

    resp = client.delete_identities(IdentityIdsToDelete=ids_to_delete)
    unprocessed = resp.get("UnprocessedIdentityIds", [])
    unprocessed_ids = [u["IdentityId"] for u in unprocessed]
    assert unprocessed_ids == [], (
        f"expected no UnprocessedIdentityIds for an interleaved batch of real + never-issued "
        f"ids, got {unprocessed_ids}"
    )

    # every real id, regardless of its position relative to a fake one, must actually be gone now
    for rid in real_ids:
        code, message = _error(lambda rid=rid: client.describe_identity(IdentityId=rid))
        assert code == "ResourceNotFoundException", (
            f"expected deleted identity {rid} to 404 on DescribeIdentity, got {code}"
        )
        expected = f"Identity '{rid}' not found."
        assert message == expected, f"expected message {expected!r}, got {message!r}"


def _create_pool(ctx, client, **extra_fields: Any) -> str:
    params = {
        "IdentityPoolName": ctx.unique_name("sim2real-idp-"),
        "AllowUnauthenticatedIdentities": True,
    }
    params.update(extra_fields)
    pool_id = client.create_identity_pool(**params)["IdentityPoolId"]
    ctx.on_cleanup(lambda: client.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


def _error(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
