"""get-principal-tag-attribute-map-nonexistent-pool-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-principal-tag-attribute-map-nonexistent-pool-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetPrincipalTagAttributeMap on a deleted pool returns ResourceNotFoundException, not a stale
    map — and the pool being gone (not merely emptied) also rejects a further Set on it."""
    ci = ctx.client("cognito-identity")
    name = ctx.unique_name("sim2real-behav-")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=True,
        SupportedLoginProviders={"graph.facebook.com": "000000000000000"},
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: _delete_pool(ci, pool_id))
    provider_name = "graph.facebook.com"

    # Establish a mapping so a stale-cache implementation would have something to leak.
    ci.set_principal_tag_attribute_map(
        IdentityPoolId=pool_id,
        IdentityProviderName=provider_name,
        PrincipalTags={"department": "sub"},
    )

    ci.delete_identity_pool(IdentityPoolId=pool_id)

    expected = f"IdentityPool '{pool_id}' not found."
    read_code, read_message = _error(
        lambda: ci.get_principal_tag_attribute_map(
            IdentityPoolId=pool_id, IdentityProviderName=provider_name
        )
    )
    assert read_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading a deleted pool's map, got {read_code!r}"
    )
    assert read_message == expected, f"expected message {expected!r}, got {read_message!r}"

    # A mutation on the dead pool must fail too — the pool is gone, not merely emptied.
    write_code, write_message = _error(
        lambda: ci.set_principal_tag_attribute_map(
            IdentityPoolId=pool_id,
            IdentityProviderName=provider_name,
            PrincipalTags={"department": "sub"},
        )
    )
    assert write_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException setting the map on a deleted pool, got {write_code!r}"
    )
    assert write_message == expected, f"expected message {expected!r}, got {write_message!r}"


def _delete_pool(ci, pool_id):
    """Teardown: the pool the check already deleted is gone, so not-found is the clean outcome."""
    from botocore.exceptions import ClientError

    try:
        ci.delete_identity_pool(IdentityPoolId=pool_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """Call fn(); return its ClientError (Code, Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
