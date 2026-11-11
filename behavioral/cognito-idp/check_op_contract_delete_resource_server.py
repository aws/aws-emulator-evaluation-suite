"""op-contract-deleteResourceServer."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteResourceServer"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteResourceServer removes the server so a subsequent DescribeResourceServer 404s and it
    drops out of ListResourceServers, frees the identifier for reuse, and rejects both an identifier
    that never existed and a repeat delete of the one just removed."""
    cognito = ctx.client("cognito-idp")
    pool = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags={"sim2real:managed": "true"},
    )["UserPool"]
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    identifier = ctx.unique_name("sim2real-api-")
    cognito.create_resource_server(UserPoolId=pool_id, Identifier=identifier, Name="sim2real server")
    cognito.describe_resource_server(UserPoolId=pool_id, Identifier=identifier)  # exists before delete
    pre_ids = {
        rs["Identifier"]
        for rs in cognito.list_resource_servers(UserPoolId=pool_id, MaxResults=50)["ResourceServers"]
    }
    assert identifier in pre_ids, f"expected {identifier} in ListResourceServers pre-delete, got {pre_ids}"

    # success path
    resp = cognito.delete_resource_server(UserPoolId=pool_id, Identifier=identifier)
    body = {k: v for k, v in resp.items() if k != "ResponseMetadata"}
    assert body == {}, f"expected an empty DeleteResourceServer response body, got {body}"

    gone_msg = f"{identifier} does not exist in user pool {pool_id}."
    err = _client_error(
        lambda: cognito.describe_resource_server(UserPoolId=pool_id, Identifier=identifier)
    )
    assert err.get("Code") == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err!r}"
    want = gone_msg
    assert err.get("Message") == want, f"expected message {want!r}, got {err.get('Message')!r}"

    post_ids = {
        rs["Identifier"]
        for rs in cognito.list_resource_servers(UserPoolId=pool_id, MaxResults=50)["ResourceServers"]
    }
    assert identifier not in post_ids, (
        f"expected {identifier} absent from ListResourceServers post-delete, got {post_ids}"
    )

    # distinct error boundary: deleting an identifier that never existed
    never = "sim2real-never-existed"
    err2 = _client_error(lambda: cognito.delete_resource_server(UserPoolId=pool_id, Identifier=never))
    assert err2.get("Code") == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err2!r}"
    want = f"{never} does not exist in user pool {pool_id}."
    assert err2.get("Message") == want, f"expected message {want!r}, got {err2.get('Message')!r}"

    # a mutation on the now-dead identifier also fails, not just a never-created one
    err3 = _client_error(
        lambda: cognito.delete_resource_server(UserPoolId=pool_id, Identifier=identifier)
    )
    assert err3.get("Code") == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err3!r}"
    want = gone_msg
    assert err3.get("Message") == want, f"expected message {want!r}, got {err3.get('Message')!r}"

    # the identifier is freed for reuse once its resource server is gone
    cognito.create_resource_server(UserPoolId=pool_id, Identifier=identifier, Name="sim2real server reused")
    reused = cognito.describe_resource_server(UserPoolId=pool_id, Identifier=identifier)["ResourceServer"]
    assert reused["Identifier"] == identifier, f"expected reused identifier {identifier}, got {reused}"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
