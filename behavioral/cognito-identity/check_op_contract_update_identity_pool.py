"""op-contract-updateIdentityPool."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "op-contract-updateIdentityPool"
GROUP = "error-semantics"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateIdentityPool applies full-replacement semantics (fields omitted from
    the update request are cleared, not merged) and raises ResourceNotFoundException
    for an unknown pool."""
    cidp = ctx.client("cognito-identity")
    pool_name = ctx.unique_name("sim2real_pool_").replace("-", "_")
    created = cidp.create_identity_pool(
        IdentityPoolName=pool_name,
        AllowUnauthenticatedIdentities=False,
        SupportedLoginProviders={"graph.facebook.com": "1234567890"},
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool_id = created["IdentityPoolId"]
    ctx.on_cleanup(lambda: cidp.delete_identity_pool(IdentityPoolId=pool_id))

    new_name = pool_name + "_renamed"
    updated = cidp.update_identity_pool(
        IdentityPoolId=pool_id,
        IdentityPoolName=new_name,
        AllowUnauthenticatedIdentities=True,
        # SupportedLoginProviders intentionally omitted: full-replacement should clear it
    )
    assert updated["IdentityPoolName"] == new_name
    assert updated["AllowUnauthenticatedIdentities"] is True
    assert not updated.get("SupportedLoginProviders"), (
        "expected SupportedLoginProviders to be cleared by full-replacement update, "
        f"got {updated.get('SupportedLoginProviders')!r}"
    )

    described = cidp.describe_identity_pool(IdentityPoolId=pool_id)
    assert described["IdentityPoolName"] == new_name
    assert described["AllowUnauthenticatedIdentities"] is True
    assert not described.get("SupportedLoginProviders")

    # error boundary: well-formed IdentityPoolId that was never created
    bogus_id = f"{ctx.region}:00000000-0000-0000-0000-000000000000"
    code, message = _error(
        lambda: cidp.update_identity_pool(
            IdentityPoolId=bogus_id,
            IdentityPoolName="does-not-matter",
            AllowUnauthenticatedIdentities=True,
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = f"IdentityPool '{bogus_id}' not found."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


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
