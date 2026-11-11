"""op-contract-describe-resource-server."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describe-resource-server"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeResourceServer returns the exact Name/Scopes recorded at creation, and
    rejects a nonexistent Identifier with ResourceNotFoundException."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)

    identifier = ctx.unique_name("sim2real-rs-")
    name = ctx.unique_name("sim2real-resource-server-")
    scopes = [
        {"ScopeName": "read", "ScopeDescription": "Read access"},
        {"ScopeName": "write", "ScopeDescription": "Write access"},
    ]
    idp.create_resource_server(UserPoolId=pool_id, Identifier=identifier, Name=name, Scopes=scopes)

    described = idp.describe_resource_server(UserPoolId=pool_id, Identifier=identifier)["ResourceServer"]
    assert described["Identifier"] == identifier, f"expected Identifier {identifier!r}, got {described['Identifier']!r}"
    assert described["Name"] == name, f"expected Name {name!r}, got {described['Name']!r}"
    assert described["Scopes"] == scopes, f"expected Scopes {scopes!r}, got {described['Scopes']!r}"

    missing_identifier = ctx.unique_name("sim2real-missing-rs-")
    code, message = _error(lambda: idp.describe_resource_server(UserPoolId=pool_id, Identifier=missing_identifier))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = f"{missing_identifier} does not exist in user pool {pool_id}."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_user_pool(ctx) -> str:
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(PoolName=ctx.unique_name("sim2real-pool-"))["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
