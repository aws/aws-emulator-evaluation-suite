"""update-identity-provider-concurrent-modification-conflict."""
from __future__ import annotations

import threading

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-identity-provider-concurrent-modification-conflict"
GROUP = "concurrency"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent UpdateIdentityProvider calls leave at least one winner, every loser failing with
    ConcurrentModificationException; a concurrent update and delete leave either the updated mapping
    or ResourceNotFoundException, each side graded on the outcome it got."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)
    provider_name = ctx.unique_name("s2rIdp")[:32]

    # Real AWS requires ProviderName to equal the provider type itself ("Google",
    # "Facebook", "LoginWithAmazon", "SignInWithApple") for the built-in social
    # provider types, rejecting any other name with InvalidParameterException. Use an
    # OIDC provider instead, which allows an arbitrary custom ProviderName.
    idp.create_identity_provider(
        UserPoolId=pool_id,
        ProviderName=provider_name,
        ProviderType="OIDC",
        ProviderDetails={
            "client_id": "111111111111-fakeclientid.example.com",
            "client_secret": "fake-oidc-client-secret",
            "attributes_request_method": "GET",
            "oidc_issuer": "https://sim2real-behav.example.com/oidc",
            "authorize_scopes": "profile email openid",
            "authorize_url": "https://sim2real-behav.example.com/oidc/authorize",
            "token_url": "https://sim2real-behav.example.com/oidc/token",
            "attributes_url": "https://sim2real-behav.example.com/oidc/userinfo",
            "jwks_uri": "https://sim2real-behav.example.com/oidc/jwks",
        },
    )
    ctx.on_cleanup(lambda: _ignore(
        lambda: idp.delete_identity_provider(UserPoolId=pool_id, ProviderName=provider_name)
    ))

    n = 10
    calls = [
        (lambda i=i: idp.update_identity_provider(
            UserPoolId=pool_id, ProviderName=provider_name,
            AttributeMapping={"email": f"email_{i}"},
        ))
        for i in range(n)
    ]
    results = _race(calls)
    successes = [r for r in results if r[0]]
    failures = [r for r in results if not r[0]]
    assert len(successes) >= 1, "expected at least one UpdateIdentityProvider racer to win"
    for _, code, message in failures:
        assert (code, message) == ("ConcurrentModificationException", _UPDATE_CONFLICT), (
            f"expected each losing UpdateIdentityProvider racer to get ConcurrentModificationException "
            f"{_UPDATE_CONFLICT!r}, got {code} {message!r}"
        )

    final = idp.describe_identity_provider(
        UserPoolId=pool_id, ProviderName=provider_name
    )["IdentityProvider"]
    final_mapping = final["AttributeMapping"].get("email", "")
    assert final_mapping.startswith("email_"), (
        f"post-race AttributeMapping does not reflect any attempted write: {final['AttributeMapping']}"
    )

    (update_ok, update_code, update_message), (delete_ok, delete_code, delete_message) = _race([
        lambda: idp.update_identity_provider(
            UserPoolId=pool_id, ProviderName=provider_name,
            AttributeMapping={"email": "email_final"},
        ),
        lambda: idp.delete_identity_provider(UserPoolId=pool_id, ProviderName=provider_name),
    ])
    if not delete_ok:
        # The update held the provider: the delete is refused and the provider keeps the update.
        assert update_ok, f"both sides of the update/delete race failed: {update_code} / {delete_code}"
        assert delete_code == "ConcurrentModificationException", (
            f"expected the losing DeleteIdentityProvider to get ConcurrentModificationException, "
            f"got {delete_code} {delete_message!r}"
        )
        final_pair = idp.describe_identity_provider(
            UserPoolId=pool_id, ProviderName=provider_name
        )["IdentityProvider"]
        assert final_pair["AttributeMapping"].get("email") == "email_final", (
            f"the update won the race but the mapping is {final_pair['AttributeMapping']}"
        )
        return

    if not update_ok:
        # The delete landed first: the update finds no provider.
        expected_update = f"Identity provider {provider_name} in User Pool {pool_id} does not exist."
        assert (update_code, update_message) == ("ResourceNotFoundException", expected_update), (
            f"expected the losing UpdateIdentityProvider to get ResourceNotFoundException "
            f"{expected_update!r}, got {update_code} {update_message!r}"
        )
    code, message = _error(
        lambda: idp.describe_identity_provider(UserPoolId=pool_id, ProviderName=provider_name)
    )
    expected_message = f"Identity provider {provider_name} for tenantId {pool_id} does not exist."
    assert (code, message) == ("ResourceNotFoundException", expected_message), (
        f"expected the deleted provider to describe as ResourceNotFoundException {expected_message!r}, "
        f"got {code} {message!r}"
    )


_UPDATE_CONFLICT = "Only one request to update the identity provider can be processed at a time."


def _error(fn):
    """Call fn(); return the ClientError (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")

def _race(calls):
    n = len(calls)
    barrier = threading.Barrier(n)
    results: list = [None] * n

    def _worker(i, fn):
        barrier.wait()
        try:
            fn()
            results[i] = (True, None, None)
        except ClientError as e:
            results[i] = (False, e.response["Error"]["Code"], e.response["Error"].get("Message"))

    threads = [threading.Thread(target=_worker, args=(i, fn)) for i, fn in enumerate(calls)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


def _ignore(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_pool(ctx):
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-"))["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
