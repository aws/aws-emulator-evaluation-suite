"""op-contract-create-resource-server."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-create-resource-server"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateResourceServer stores Identifier, Name and Scopes as DescribeResourceServer returns
    them, and with an unknown UserPoolId it is refused with ResourceNotFoundException and the exact
    message, creating nothing under the real pool either."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)

    identifier = ctx.unique_name("sim2real-rs-")
    name = ctx.unique_name("sim2real-resource-server-")
    scopes = [{"ScopeName": "read", "ScopeDescription": "Read access"}]

    created = idp.create_resource_server(
        UserPoolId=pool_id, Identifier=identifier, Name=name, Scopes=scopes
    )["ResourceServer"]
    assert created["Identifier"] == identifier, (
        f"expected Identifier {identifier!r}, got {created['Identifier']!r}"
    )
    assert created["Name"] == name, f"expected Name {name!r}, got {created['Name']!r}"
    assert created["Scopes"] == scopes, f"expected Scopes {scopes!r}, got {created['Scopes']!r}"

    described = idp.describe_resource_server(UserPoolId=pool_id, Identifier=identifier)["ResourceServer"]
    assert described["Name"] == name, (
        f"independent describe returned Name {described['Name']!r}, expected {name!r}"
    )
    assert described["Scopes"] == scopes, (
        f"independent describe returned Scopes {described['Scopes']!r}, expected {scopes!r}"
    )

    bogus_pool_id = pool_id[:-3] + "xyz"
    neg_identifier = ctx.unique_name("sim2real-rs-")
    code, message = _error(
        lambda: idp.create_resource_server(
            UserPoolId=bogus_pool_id,
            Identifier=neg_identifier,
            Name="whatever",
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected_message = f"User pool {bogus_pool_id} does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect-absent, at an independent read: the rejected create must not have been applied under
    # the real pool either -- a target that ignores an unrecognised UserPoolId and falls back to
    # some default would otherwise pass despite accepting the mutation it claims to have refused.
    absent_code, absent_message = _error(
        lambda: idp.describe_resource_server(UserPoolId=pool_id, Identifier=neg_identifier)
    )
    assert absent_code == "ResourceNotFoundException", (
        f"identifier {neg_identifier!r} from the rejected create was found under the real pool "
        f"{pool_id!r} (describe returned {absent_code!r} instead of ResourceNotFoundException)"
    )
    expected_absent = f"{neg_identifier} does not exist in user pool {pool_id}."
    assert absent_message == expected_absent, (
        f"expected message {expected_absent!r}, got {absent_message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an over-permissive target accepting a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_user_pool(ctx) -> str:
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
