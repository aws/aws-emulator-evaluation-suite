"""op-contract-list-resource-servers."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-list-resource-servers"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListResourceServers enumerates resource servers with their scopes; a bogus pool id 404s."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-pool-"))["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    identifier = ctx.unique_name("sim2real-behav-api-")
    idp.create_resource_server(
        UserPoolId=pool_id,
        Identifier=identifier,
        Name="fidelity-api",
        Scopes=[{"ScopeName": "read", "ScopeDescription": "read access"}],
    )

    servers = idp.list_resource_servers(UserPoolId=pool_id, MaxResults=25)["ResourceServers"]
    matches = [s for s in servers if s["Identifier"] == identifier]
    assert len(matches) == 1, f"expected exactly one match for {identifier}, got {servers}"
    assert matches[0]["Name"] == "fidelity-api", f"expected Name fidelity-api, got {matches[0]['Name']}"
    assert matches[0]["Scopes"][0]["ScopeName"] == "read", (
        f"expected ScopeName read, got {matches[0]['Scopes']}"
    )

    bogus_id = pool_id[:-4] + "zzzz"
    err = _client_error(lambda: idp.list_resource_servers(UserPoolId=bogus_id, MaxResults=25))
    assert err.get("Code") == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err!r}"
    want = f"User pool {bogus_id} does not exist."
    assert err.get("Message") == want, f"expected message {want!r}, got {err.get('Message')!r}"


def _client_error(fn):
    """Call fn() and return its error dict; raise if the call unexpectedly succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
