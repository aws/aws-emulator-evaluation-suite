"""op-contract-describeIdentityPool."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "op-contract-describeIdentityPool"
GROUP = "error-semantics"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeIdentityPool echoes back the configuration supplied at creation and
    raises ResourceNotFoundException for a well-formed but nonexistent IdentityPoolId."""
    cidp = ctx.client("cognito-identity")
    pool_name = ctx.unique_name("sim2real_pool_").replace("-", "_")
    created = cidp.create_identity_pool(
        IdentityPoolName=pool_name,
        AllowUnauthenticatedIdentities=False,
        AllowClassicFlow=True,
        SupportedLoginProviders={"graph.facebook.com": "1234567890"},
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool_id = created["IdentityPoolId"]
    ctx.on_cleanup(lambda: cidp.delete_identity_pool(IdentityPoolId=pool_id))

    described = cidp.describe_identity_pool(IdentityPoolId=pool_id)
    assert described["IdentityPoolId"] == pool_id, (
        f"expected IdentityPoolId {pool_id!r}, got {described['IdentityPoolId']!r}"
    )
    assert described["IdentityPoolName"] == pool_name, (
        f"expected IdentityPoolName {pool_name!r}, got {described['IdentityPoolName']!r}"
    )
    assert described["AllowUnauthenticatedIdentities"] is False, (
        f"expected AllowUnauthenticatedIdentities False, got {described['AllowUnauthenticatedIdentities']!r}"
    )
    assert described.get("AllowClassicFlow") is True, (
        f"expected AllowClassicFlow True, got {described.get('AllowClassicFlow')!r}"
    )
    assert described.get("SupportedLoginProviders") == {"graph.facebook.com": "1234567890"}, (
        f"expected echoed SupportedLoginProviders, got {described.get('SupportedLoginProviders')!r}"
    )

    # error boundary: well-formed IdentityPoolId (matches "<region>:<uuid>") never created
    bogus_id = f"{ctx.region}:00000000-0000-0000-0000-000000000000"
    code, message = _error(lambda: cidp.describe_identity_pool(IdentityPoolId=bogus_id))
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
