"""environment-variable-unicode-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "environment-variable-unicode-round-trip"
GROUP = "environment-variables"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Environment variable values containing unicode survive Put/Get byte-for-byte."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx)

    unicode_value = 'h\u00e9llo W\u00f6rld \u65e5\u672c\u8a9e \U0001f680 \u03a9\u2248\u00e7\u221a\u222b\u02dc\u00b5\u2264\u2265\u00f7 "quoted" \\backslash\\ \u043a\u043b\u044e\u0447'
    env_vars = {"UnicodeVar": unicode_value, "PlainVar": "plain-ascii-value"}

    put_resp = appsync.put_graphql_api_environment_variables(
        apiId=api_id, environmentVariables=env_vars
    )
    assert put_resp["environmentVariables"]["UnicodeVar"] == unicode_value, (
        f"PutGraphqlApiEnvironmentVariables mangled unicode value: "
        f"{put_resp['environmentVariables'].get('UnicodeVar')!r} != {unicode_value!r}"
    )

    get_resp = appsync.get_graphql_api_environment_variables(apiId=api_id)
    returned = get_resp["environmentVariables"]
    assert returned["UnicodeVar"] == unicode_value, (
        f"GetGraphqlApiEnvironmentVariables mangled unicode value: "
        f"{returned.get('UnicodeVar')!r} != {unicode_value!r}"
    )
    assert returned["PlainVar"] == "plain-ascii-value"
    assert len(returned) == 2, f"expected exactly 2 env vars, got {list(returned)}"


def _create_graphql_api(ctx) -> str:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-behav-")
    resp = appsync.create_graphql_api(
        name=name, authenticationType="API_KEY", tags={"sim2real": CHECK}
    )
    api_id = resp["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
