"""environment-variables-unicode-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "environment-variables-unicode-round-trip"
GROUP = "representation"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode values (accented Latin, CJK, emoji) round-trip unchanged through Put/Get
    GraphqlApiEnvironmentVariables; env var values are opaque strings.
    """
    appsync = ctx.client("appsync")

    api_name = _safe_graphql_name(ctx, "sim2real_envvarapi")
    api = appsync.create_graphql_api(
        name=api_name,
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    unicode_value = "héllo wörld – 你好 🎉 café"
    env_vars = {"GREETING": unicode_value, "PLAINKEY": "plain-ascii-value"}

    put_result = appsync.put_graphql_api_environment_variables(
        apiId=api_id, environmentVariables=env_vars
    )["environmentVariables"]
    assert put_result["GREETING"] == unicode_value, (
        f"PutGraphqlApiEnvironmentVariables mangled unicode value: "
        f"{put_result.get('GREETING')!r} != {unicode_value!r}"
    )

    fetched = appsync.get_graphql_api_environment_variables(apiId=api_id)["environmentVariables"]
    assert fetched["GREETING"] == unicode_value, (
        f"GetGraphqlApiEnvironmentVariables mangled unicode value: "
        f"{fetched.get('GREETING')!r} != {unicode_value!r}"
    )
    assert fetched["PLAINKEY"] == "plain-ascii-value", (
        f"expected PLAINKEY == 'plain-ascii-value', got {fetched.get('PLAINKEY')!r}"
    )
    assert set(fetched) == set(env_vars), (
        f"expected exactly the keys {sorted(env_vars)}, got {sorted(fetched)}"
    )


def _safe_graphql_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    cleaned = "".join(c if (c.isalnum() or c == "_") else "_" for c in raw)
    if not cleaned or not (cleaned[0].isalpha() or cleaned[0] == "_"):
        cleaned = "a" + cleaned
    return cleaned[:64]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
