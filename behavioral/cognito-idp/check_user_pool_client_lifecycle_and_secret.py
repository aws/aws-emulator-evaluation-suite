"""user-pool-client-lifecycle-and-secret."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "user-pool-client-lifecycle-and-secret"
GROUP = 'pool-level-lifecycle'
SERVICES = ['cognito-idp']


def _error(fn):
    """Call fn(); return its ClientError (code, HTTP status, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_unless_gone(fn, gone_code):
    """Teardown for a resource the check itself deletes: a refusal naming it gone is success."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != gone_code:
            raise


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """App client: create -> describe -> update -> delete, with secret rotation
    (AddUserPoolClientSecret/ListUserPoolClientSecrets/DeleteUserPoolClientSecret)
    reflected consistently across list/get."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    client = c.create_user_pool_client(UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"), GenerateSecret=True)["UserPoolClient"]
    client_id = client["ClientId"]
    ctx.on_cleanup(
        lambda _p=pool_id, _c=client_id: _delete_unless_gone(
            lambda: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c), "ResourceNotFoundException"
        )
    )
    original_secret = client["ClientSecret"]
    assert original_secret, "CreateUserPoolClient with GenerateSecret=True returned no ClientSecret"

    desc = c.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)["UserPoolClient"]
    assert desc["ClientSecret"] == original_secret, (
        f"DescribeUserPoolClient disagrees with the create response: "
        f"expected {original_secret!r}, got {desc['ClientSecret']!r}"
    )

    client_ids = [
        cc["ClientId"]
        for cc in c.list_user_pool_clients(UserPoolId=pool_id)["UserPoolClients"]
    ]
    assert client_id in client_ids, f"{client_id} missing from ListUserPoolClients: {client_ids}"

    added = c.add_user_pool_client_secret(UserPoolId=pool_id, ClientId=client_id)[
        "ClientSecretDescriptor"
    ]
    new_secret_id = added["ClientSecretId"]
    assert added["ClientSecretValue"], "AddUserPoolClientSecret returned no ClientSecretValue"

    secret_ids = [
        s["ClientSecretId"]
        for s in c.list_user_pool_client_secrets(UserPoolId=pool_id, ClientId=client_id)["ClientSecrets"]
    ]
    assert new_secret_id in secret_ids, "new secret missing from ListUserPoolClientSecrets"

    c.delete_user_pool_client_secret(
        UserPoolId=pool_id, ClientId=client_id, ClientSecretId=new_secret_id
    )
    secret_ids_after = [
        s["ClientSecretId"]
        for s in c.list_user_pool_client_secrets(UserPoolId=pool_id, ClientId=client_id)["ClientSecrets"]
    ]
    assert new_secret_id not in secret_ids_after, "secret still listed after delete"

    secret_delete_again_code, secret_delete_again_status, secret_delete_again_message = _error(
        lambda: c.delete_user_pool_client_secret(
            UserPoolId=pool_id, ClientId=client_id, ClientSecretId=new_secret_id
        )
    )
    assert secret_delete_again_code == "ResourceNotFoundException", (
        f"deleting an already-deleted secret: expected ResourceNotFoundException, "
        f"got {secret_delete_again_code}"
    )
    assert secret_delete_again_status == 400, (
        f"deleting an already-deleted secret: expected HTTP 400, got {secret_delete_again_status}"
    )
    expected_message = "Client secret does not exist"
    assert secret_delete_again_message == expected_message, f"expected the message {expected_message!r}, got {secret_delete_again_message!r}"

    new_name = ctx.unique_name("sim2real-behav-cip-client-renamed-")
    c.update_user_pool_client(UserPoolId=pool_id, ClientId=client_id, ClientName=new_name)
    desc2 = c.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)["UserPoolClient"]
    assert desc2["ClientName"] == new_name, f"expected ClientName {new_name!r}, got {desc2['ClientName']!r}"

    c.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id)

    code, status, message = _error(
        lambda: c.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert status == 400, f"describing a deleted client: expected HTTP 400, got {status}"
    expected_message = "User pool client does not exist."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    client_ids_after = [
        cc["ClientId"]
        for cc in c.list_user_pool_clients(UserPoolId=pool_id)["UserPoolClients"]
    ]
    assert client_id not in client_ids_after, "deleted client still in ListUserPoolClients"

    update_dead_client_code, update_dead_client_status, update_dead_client_message = _error(
        lambda: c.update_user_pool_client(UserPoolId=pool_id, ClientId=client_id, ClientName=new_name)
    )
    assert update_dead_client_code == "ResourceNotFoundException", (
        f"mutating a deleted client: expected ResourceNotFoundException, got {update_dead_client_code}"
    )
    assert update_dead_client_status == 400, (
        f"mutating a deleted client: expected HTTP 400, got {update_dead_client_status}"
    )
    expected_message = "User pool client does not exist."
    assert update_dead_client_message == expected_message, f"expected the message {expected_message!r}, got {update_dead_client_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
