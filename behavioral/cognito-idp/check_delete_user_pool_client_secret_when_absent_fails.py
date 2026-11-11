"""delete-user-pool-client-secret-when-absent-fails."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-user-pool-client-secret-when-absent-fails"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteUserPoolClientSecret for a secret id never issued to the client answers
    ResourceNotFoundException "Client secret does not exist", while deleting a secret
    AddUserPoolClientSecret issued removes it from ListUserPoolClientSecrets."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-"), UserPoolTags=_TAGS
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    # AddUserPoolClientSecret needs a secret-enabled client; on a GenerateSecret=False client it
    # is refused with InvalidParameterException ("secret not enabled").
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        GenerateSecret=True,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: _ignore(lambda: idp.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id)))

    original_ids = {
        s["ClientSecretId"]
        for s in idp.list_user_pool_client_secrets(UserPoolId=pool_id, ClientId=client_id)[
            "ClientSecrets"
        ]
    }
    assert original_ids, "a GenerateSecret=True client must start with its own secret listed"

    # Positive control: AddUserPoolClientSecret issues a real, independently
    # observable secret id, and deleting that real id succeeds.
    added = idp.add_user_pool_client_secret(UserPoolId=pool_id, ClientId=client_id)[
        "ClientSecretDescriptor"
    ]
    real_secret_id = added["ClientSecretId"]
    assert real_secret_id not in original_ids, (
        f"AddUserPoolClientSecret must issue a fresh id, got {real_secret_id!r} in {original_ids}"
    )
    after_add = {
        s["ClientSecretId"]
        for s in idp.list_user_pool_client_secrets(UserPoolId=pool_id, ClientId=client_id)[
            "ClientSecrets"
        ]
    }
    assert real_secret_id in after_add, after_add

    idp.delete_user_pool_client_secret(
        UserPoolId=pool_id, ClientId=client_id, ClientSecretId=real_secret_id
    )
    after_delete = {
        s["ClientSecretId"]
        for s in idp.list_user_pool_client_secrets(UserPoolId=pool_id, ClientId=client_id)[
            "ClientSecrets"
        ]
    }
    assert real_secret_id not in after_delete, (
        f"real secret {real_secret_id} still listed after a successful delete: {after_delete}"
    )
    assert original_ids <= after_delete, after_delete

    # The contract under test: an id never issued for this client at all -- as
    # opposed to one that was issued and is now gone -- is rejected the same way.
    bogus_secret_id = str(uuid.uuid4())
    code, message = _error(lambda: idp.delete_user_pool_client_secret(
        UserPoolId=pool_id, ClientId=client_id, ClientSecretId=bogus_secret_id,
    ))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException deleting an absent client secret, got {code!r}"
    )
    assert message == "Client secret does not exist", f"unexpected message {message!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses cannot pass as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to fail, but it SUCCEEDED and returned {result!r}")


def _ignore(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
