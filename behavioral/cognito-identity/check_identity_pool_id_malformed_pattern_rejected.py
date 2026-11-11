"""identity-pool-id-malformed-pattern-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "identity-pool-id-malformed-pattern-rejected"
GROUP = "representation"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeIdentityPool rejects an IdentityPoolId that breaks the ^[\\w-]+:[0-9a-f-]+$ pattern
    with ValidationException and the exact message, while a real pool id still describes."""
    ci = ctx.client("cognito-identity")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-"),
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    malformed_id = "not-a-valid-identity-pool-id"  # missing the required "region:guid" shape
    code, message = _error(lambda: ci.describe_identity_pool(IdentityPoolId=malformed_id))
    assert code == "ValidationException", f"unexpected error code: {code!r}"
    expected = (
        f"1 validation error detected: Value '{malformed_id}' at 'identityPoolId' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: [\\w-]+:[0-9a-f-]+"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


    # Positive control: the well-formed, real pool ID is unaffected and still readable.
    described = ci.describe_identity_pool(IdentityPoolId=pool_id)
    assert described["IdentityPoolId"] == pool_id, (
        f"expected {pool_id!r}, got {described.get('IdentityPoolId')!r}"
    )


def _error(fn):
    """Call fn(); return its ClientError (Code, Message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS rejects is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
