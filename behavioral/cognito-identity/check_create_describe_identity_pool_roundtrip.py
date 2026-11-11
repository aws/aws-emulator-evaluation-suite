"""create-describe-identity-pool-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-describe-identity-pool-roundtrip"
GROUP = "lifecycle"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateIdentityPool's semantic fields round-trip exactly through DescribeIdentityPool,
    and the pool is gone-and-unusable at the destination once deleted."""
    ci = ctx.client("cognito-identity")
    name = ctx.unique_name("sim2real-behav-")
    login_providers = {"graph.facebook.com": "1234567890123456"}
    created = ci.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=True,
        AllowClassicFlow=False,
        SupportedLoginProviders=login_providers,
    )
    pool_id = created["IdentityPoolId"]
    ctx.on_cleanup(lambda: _delete_pool(ci, pool_id))

    assert created["IdentityPoolName"] == name, (
        f"expected CreateIdentityPool to echo name {name!r}, got {created['IdentityPoolName']!r}"
    )
    assert created["AllowUnauthenticatedIdentities"] is True, (
        f"expected CreateIdentityPool to echo AllowUnauthenticatedIdentities=True, "
        f"got {created['AllowUnauthenticatedIdentities']!r}"
    )
    assert created["SupportedLoginProviders"] == login_providers, (
        f"expected CreateIdentityPool to echo SupportedLoginProviders {login_providers!r}, "
        f"got {created['SupportedLoginProviders']!r}"
    )

    described = ci.describe_identity_pool(IdentityPoolId=pool_id)
    assert described["IdentityPoolId"] == pool_id, (
        f"expected DescribeIdentityPool to return pool id {pool_id!r}, got {described['IdentityPoolId']!r}"
    )
    assert described["IdentityPoolName"] == name, (
        f"expected DescribeIdentityPool to reflect name {name!r}, got {described['IdentityPoolName']!r}"
    )
    assert described["AllowUnauthenticatedIdentities"] is True, (
        f"expected DescribeIdentityPool to reflect AllowUnauthenticatedIdentities=True, "
        f"got {described['AllowUnauthenticatedIdentities']!r}"
    )
    assert described["AllowClassicFlow"] is False, (
        f"expected DescribeIdentityPool to reflect AllowClassicFlow=False, "
        f"got {described['AllowClassicFlow']!r}"
    )
    assert described["SupportedLoginProviders"] == login_providers, (
        f"expected DescribeIdentityPool to reflect SupportedLoginProviders {login_providers!r}, "
        f"got {described['SupportedLoginProviders']!r}"
    )

    ci.delete_identity_pool(IdentityPoolId=pool_id)
    code, message = _error(lambda: ci.describe_identity_pool(IdentityPoolId=pool_id))
    assert code == "ResourceNotFoundException", (
        f"expected DescribeIdentityPool on a deleted pool to raise ResourceNotFoundException, got {code!r}"
    )
    expected = f"IdentityPool '{pool_id}' not found."
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


def _delete_pool(ci, pool_id):
    """Teardown that tolerates a pool the check itself already deleted."""
    from botocore.exceptions import ClientError

    try:
        ci.delete_identity_pool(IdentityPoolId=pool_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
