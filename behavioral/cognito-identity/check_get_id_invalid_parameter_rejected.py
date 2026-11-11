"""get-id-invalid-parameter-rejected."""

from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-id-invalid-parameter-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-identity"]


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """GetId with a malformed IdentityPoolId (not REGION:GUID) fails with
    ValidationException (the shape's regex pattern constraint); the same call
    against a real pool succeeds and returns a well-formed IdentityId."""
    ci = ctx.client("cognito-identity")
    pool_id = _create_pool(ctx, ci)

    # Negative: malformed pool id (no region:guid structure, illegal characters).
    bad_pool_id = "not-a-valid-pool-id!!"
    code, message = _refusal(lambda: ci.get_id(IdentityPoolId=bad_pool_id))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}: {message!r}"
    assert message == (
        f"1 validation error detected: Value '{bad_pool_id}' at 'identityPoolId' failed to "
        r"satisfy constraint: Member must satisfy regular expression pattern: [\w-]+:[0-9a-f-]+"
    ), message

    # Positive control: the real pool id succeeds and yields a well-formed IdentityId.
    resp = ci.get_id(IdentityPoolId=pool_id)
    identity_id = resp["IdentityId"]
    assert re.match(r"^[\w-]+:[0-9a-f-]+$", identity_id), identity_id
    assert identity_id.startswith(f"{ctx.region}:"), (
        f"expected identity id region prefix {ctx.region}:, got {identity_id!r}"
    )

    desc = ci.describe_identity(IdentityId=identity_id)
    assert desc["IdentityId"] == identity_id, (
        f"expected describe_identity to report {identity_id!r}, got {desc['IdentityId']!r}"
    )


def _create_pool(ctx, ci, *, unauth: bool = True) -> str:
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=unauth,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


def _refusal(fn):
    """Call fn(); return the refusal's (Code, Message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected GetId to be rejected, but it succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
