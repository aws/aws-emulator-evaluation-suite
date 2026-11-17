"""update-resource-server-rejects-malformed-scope-name."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-resource-server-rejects-malformed-scope-name"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateResourceServer refuses a ScopeName containing a forward slash and leaves
    the stored scopes unchanged; a name with the same text minus the slash succeeds."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    identifier = ctx.unique_name("sim2real-behav-api-")
    idp.create_resource_server(
        UserPoolId=pool_id,
        Identifier=identifier,
        Name="original-name",
        Scopes=[{"ScopeName": "read", "ScopeDescription": "read access"}],
    )

    code, message = _error(
        lambda: idp.update_resource_server(
            UserPoolId=pool_id,
            Identifier=identifier,
            Name="original-name",
            Scopes=[{"ScopeName": "a/b", "ScopeDescription": "slash in name"}],
        )
    )
    expected = (
        "1 validation error detected: Value 'a/b' at 'scopes.1.member.scopeName' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: "
        "[\\x21\\x23-\\x2E\\x30-\\x5B\\x5D-\\x7E]+"
    )
    assert (code, message) == ("InvalidParameterException", expected), (
        f"expected ('InvalidParameterException', {expected!r}), got {(code, message)!r}"
    )

    after_reject = idp.describe_resource_server(UserPoolId=pool_id, Identifier=identifier)["ResourceServer"]
    scope_names = {s["ScopeName"] for s in after_reject["Scopes"]}
    assert scope_names == {"read"}, f"expected the original scopes unchanged, got {scope_names}"

    # positive control: the same text with the slash removed succeeds, proving the
    # rejection above is specific to the slash and not a blanket refusal.
    idp.update_resource_server(
        UserPoolId=pool_id,
        Identifier=identifier,
        Name="original-name",
        Scopes=[{"ScopeName": "a-b", "ScopeDescription": "no slash in name"}],
    )
    after_accept = idp.describe_resource_server(UserPoolId=pool_id, Identifier=identifier)["ResourceServer"]
    accepted_names = {s["ScopeName"] for s in after_accept["Scopes"]}
    assert accepted_names == {"a-b"}, f"expected a-b, got {accepted_names}"


def _error(fn):
    """Call fn(); return its (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
