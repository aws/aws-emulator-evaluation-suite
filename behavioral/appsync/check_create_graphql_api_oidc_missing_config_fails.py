"""create-graphql-api-oidc-missing-config-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-graphql-api-oidc-missing-config-fails"
GROUP = 'overly-permissive'
SERVICES = ['appsync']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateGraphqlApi with authenticationType=OPENID_CONNECT but no openIDConnectConfig is rejected BadRequestException."""
    svc = ctx.client("appsync")

    bad_name = ctx.unique_name("sim2real-behav-appsync-api-oidc-")
    error = _error(
        lambda: svc.create_graphql_api(name=bad_name, authenticationType="OPENID_CONNECT")
    )
    expected = ("BadRequestException", "OpenID Connect Config missing")
    assert error == expected, (
        f"expected {expected} for OPENID_CONNECT auth with no config, got {error}"
    )

    # Effect is absent: no API with that name exists anywhere in the account.
    found = False
    paginator = svc.get_paginator("list_graphql_apis")
    for page in paginator.paginate():
        if any(a["name"] == bad_name for a in page.get("graphqlApis", [])):
            found = True
            break
    assert not found, f"an API was created despite the missing openIDConnectConfig: {bad_name!r}"

    # Positive control: the identical request WITH a valid openIDConnectConfig succeeds,
    # proving the account and credentials are otherwise healthy for OIDC-authenticated APIs.
    ok_name = ctx.unique_name("sim2real-behav-appsync-api-oidc-ok-")
    api = svc.create_graphql_api(
        name=ok_name,
        authenticationType="OPENID_CONNECT",
        openIDConnectConfig={"issuer": "https://example.com/"},
        tags={"sim2real-check": CHECK},
    )["graphqlApi"]
    ctx.on_cleanup(lambda: svc.delete_graphql_api(apiId=api["apiId"]))
    assert api["name"] == ok_name, f"expected {ok_name!r}, got {api.get('name')!r}"

    # Independent read at the destination: don't trust the create call's own echo.
    fetched = svc.get_graphql_api(apiId=api["apiId"])["graphqlApi"]
    assert fetched["name"] == ok_name, f"expected {ok_name!r}, got {fetched.get('name')!r}"
    assert fetched["openIDConnectConfig"]["issuer"] == "https://example.com/", (
        f"expected issuer https://example.com/, got {fetched.get('openIDConnectConfig')!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
