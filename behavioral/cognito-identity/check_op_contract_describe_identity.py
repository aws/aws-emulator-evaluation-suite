"""op-contract-describeIdentity."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "op-contract-describeIdentity"
GROUP = "error-semantics"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeIdentity returns the identity's IdentityId/Logins on success and
    ResourceNotFoundException for a well-formed but nonexistent IdentityId."""
    cidp = ctx.client("cognito-identity")
    pool_id = _create_identity_pool(ctx, allow_unauth=True)

    identity_id = cidp.get_id(IdentityPoolId=pool_id)["IdentityId"]

    described = cidp.describe_identity(IdentityId=identity_id)
    assert described["IdentityId"] == identity_id, (
        f"expected IdentityId {identity_id!r}, got {described.get('IdentityId')!r}"
    )
    # unauthenticated identity created with no Logins supplied -> no linked logins
    assert described.get("Logins", []) == [], f"expected no Logins, got {described.get('Logins')!r}"

    # error boundary: well-formed IdentityId (matches "<region>:<uuid>") that was never created
    bogus_id = f"{ctx.region}:00000000-0000-0000-0000-000000000000"
    code, message = _error(lambda: cidp.describe_identity(IdentityId=bogus_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = f"Identity '{bogus_id}' not found."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _create_identity_pool(ctx, *, allow_unauth: bool) -> str:
    cidp = ctx.client("cognito-identity")
    pool = cidp.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_pool_").replace("-", "_"),
        AllowUnauthenticatedIdentities=allow_unauth,
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool_id = pool["IdentityPoolId"]
    ctx.on_cleanup(lambda: cidp.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


def _error(fn) -> tuple[str, str | None]:
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
