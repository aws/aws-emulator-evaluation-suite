"""describe-unknown-resource-server-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-unknown-resource-server-fails"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeResourceServer on a resource server never created fails with ResourceNotFoundException
    and its exact message, while the same call on one just created returns its identifier."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))

    real_identifier = f"https://{ctx.unique_name('sim2real-behav-cip-rs-')}.example.com"
    real_name = ctx.unique_name("sim2real-behav-cip-rs-")
    c.create_resource_server(
        UserPoolId=pool_id,
        Identifier=real_identifier,
        Name=real_name,
        Scopes=[{"ScopeName": "read", "ScopeDescription": "read scope"}],
    )
    positive = c.describe_resource_server(UserPoolId=pool_id, Identifier=real_identifier)["ResourceServer"]
    assert positive["Identifier"] == real_identifier, (
        f"positive control failed: expected DescribeResourceServer to return {real_identifier}, got {positive.get('Identifier')}"
    )

    unknown_identifier = "https://never-created.example.com"
    code, message = _error(
        lambda: c.describe_resource_server(UserPoolId=pool_id, Identifier=unknown_identifier)
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for an unknown resource server, got {code}"
    )
    expected = f"{unknown_identifier} does not exist in user pool {pool_id}."
    assert message == expected, (
        f"expected the exact ResourceNotFoundException message {expected!r}, got {message!r}"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because a target that accepts a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
