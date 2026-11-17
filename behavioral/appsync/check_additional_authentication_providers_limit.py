"""additional-authentication-providers-limit."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "additional-authentication-providers-limit"
GROUP = "auth"
SERVICES = ["appsync"]

_LIMIT = 50


def _providers(issuer_prefix: str, n: int):
    return [
        {
            "authenticationType": "OPENID_CONNECT",
            "openIDConnectConfig": {"issuer": f"https://{issuer_prefix}-{i}.example.com"},
        }
        for i in range(n)
    ]


def _issuers(providers) -> set:
    return {p["openIDConnectConfig"]["issuer"] for p in providers}


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateGraphqlApi accepts up to 50 additionalAuthenticationProviders and rejects 51,
    leaving the prior 50 providers in place."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": "behavioral"},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]
    name = api["name"]

    at_limit = _providers("sim2real-auth-a", _LIMIT)
    svc.update_graphql_api(
        apiId=api_id,
        name=name,
        authenticationType="API_KEY",
        additionalAuthenticationProviders=at_limit,
    )
    got = svc.get_graphql_api(apiId=api_id)["graphqlApi"]
    assert _issuers(got["additionalAuthenticationProviders"]) == _issuers(at_limit), (
        f"expected exactly the {_LIMIT} issuers just set, got "
        f"{sorted(_issuers(got['additionalAuthenticationProviders']))}"
    )

    over_limit = _providers("sim2real-auth-b", _LIMIT + 1)
    code, message = _error(
        lambda: svc.update_graphql_api(
            apiId=api_id,
            name=name,
            authenticationType="API_KEY",
            additionalAuthenticationProviders=over_limit,
        )
    )
    assert code == "BadRequestException", (
        f"expected BadRequestException once the {_LIMIT}-additional-provider ceiling is "
        f"exceeded, got {code}: {message!r}"
    )
    assert message == (
        f"Maximum number of additional authentication providers is {_LIMIT}. "
        f"You added {_LIMIT + 1}."
    ), f"expected AWS's exact ceiling message naming the {_LIMIT}-provider limit, got {message!r}"

    unchanged = svc.get_graphql_api(apiId=api_id)["graphqlApi"]
    assert _issuers(unchanged["additionalAuthenticationProviders"]) == _issuers(at_limit), (
        f"the rejected UpdateGraphqlApi must leave the providers unchanged: expected "
        f"{sorted(_issuers(at_limit))}, got "
        f"{sorted(_issuers(unchanged['additionalAuthenticationProviders']))}"
    )

    restored_set = _providers("sim2real-auth-c", _LIMIT)
    restored = svc.update_graphql_api(
        apiId=api_id,
        name=name,
        authenticationType="API_KEY",
        additionalAuthenticationProviders=restored_set,
    )["graphqlApi"]
    assert _issuers(restored["additionalAuthenticationProviders"]) == _issuers(restored_set), (
        f"an identical-shape update back at {_LIMIT} providers must succeed, got "
        f"{sorted(_issuers(restored['additionalAuthenticationProviders']))}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
