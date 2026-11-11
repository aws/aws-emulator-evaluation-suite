"""op-contract-list-user-pool-clients."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-list-user-pool-clients"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListUserPoolClients enumerates the pool's app clients; a bogus pool id 404s."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    names = {ctx.unique_name(f"sim2real-behav-client-{i}-") for i in range(2)}
    ids = set()
    for n in names:
        c = idp.create_user_pool_client(UserPoolId=pool_id, ClientName=n)["UserPoolClient"]
        ids.add(c["ClientId"])

    listed = idp.list_user_pool_clients(UserPoolId=pool_id, MaxResults=25)["UserPoolClients"]
    listed_names = {c["ClientName"] for c in listed}
    listed_ids = {c["ClientId"] for c in listed}
    assert names.issubset(listed_names), f"expected {names} subset of {listed_names}"
    assert ids.issubset(listed_ids), f"expected {ids} subset of {listed_ids}"

    bogus_id = pool_id[:-4] + "zzzz"
    err = _client_error(lambda: idp.list_user_pool_clients(UserPoolId=bogus_id, MaxResults=25))
    assert err.get("Code") == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err!r}"
    want = f"User pool {bogus_id} does not exist."
    assert err.get("Message") == want, f"expected message {want!r}, got {err.get('Message')!r}"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
