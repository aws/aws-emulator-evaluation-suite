"""delete-identities-partial-unprocessed."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-identities-partial-unprocessed"
GROUP = "identity-lifecycle"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteIdentities with a real and a never-issued IdentityId reports neither as unprocessed, and the real
    identity then fails DescribeIdentity with ResourceNotFoundException and its exact message.
    """
    ci = ctx.client("cognito-identity")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-"),
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    real_identity = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    # A well-formed IdentityId that was never issued anywhere (region prefix deliberately
    # mismatched from the endpoint's region, to also rule out same-region collision).
    other_region = "us-west-2" if ctx.region != "us-west-2" else "eu-west-1"
    fake_identity = f"{other_region}:00000000-0000-0000-0000-000000000000"

    resp = ci.delete_identities(IdentityIdsToDelete=[real_identity, fake_identity])
    unprocessed_ids = {u["IdentityId"] for u in resp.get("UnprocessedIdentityIds", [])}

    assert real_identity not in unprocessed_ids, (
        f"a real identity should be processed (deleted), but it's in UnprocessedIdentityIds: {resp}"
    )
    assert fake_identity not in unprocessed_ids, (
        "a never-issued identity id is silently no-op'd by real AWS, not reported as "
        f"unprocessed, got {resp}"
    )
    assert not unprocessed_ids, f"expected no unprocessed identities at all, got {resp}"

    # The real identity is gone -- the presence of the never-issued id in the same
    # batch must not have blocked or otherwise affected the real deletion.
    describe_code, message = _error(lambda: ci.describe_identity(IdentityId=real_identity))
    assert describe_code == "ResourceNotFoundException", f"got {describe_code!r}"
    expected = f"Identity '{real_identity}' not found."
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
