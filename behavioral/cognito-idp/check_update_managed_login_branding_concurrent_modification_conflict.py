"""update-managed-login-branding-concurrent-modification-conflict."""
from __future__ import annotations

import threading

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-managed-login-branding-concurrent-modification-conflict"
GROUP = "concurrency"
SERVICES = ["cognito-idp"]

CONFLICT_MESSAGE = "Only one request to modify a ManagedLoginBranding can be processed at a time"
NOT_FOUND_MESSAGE = "ManagedLoginBranding does not exist."


@tags("axis:happy-path", "cap:c1", "plane:control")
def run(ctx) -> None:
    """Racing updates, then an update/delete pair, on one managed login branding: each race has a
    winner, losers get only ConcurrentModificationException or ResourceNotFoundException with exact
    messages, and the branding is gone exactly when a delete won."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)
    client_id = _create_client(ctx, pool_id)

    state: dict[str, str] = {}

    def _ensure_branding():
        if "branding_id" in state:
            try:
                idp.describe_managed_login_branding(
                    UserPoolId=pool_id, ManagedLoginBrandingId=state["branding_id"],
                )
                return
            except ClientError as e:
                if e.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        try:
            branding = idp.create_managed_login_branding(
                UserPoolId=pool_id, ClientId=client_id, UseCognitoProvidedValues=True,
            )["ManagedLoginBranding"]
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("FeatureUnavailableInTierException", "OperationNotEnabledException"):
                raise AssertionError(f"unreachable: managed login branding not available: {code}")
            raise
        state["branding_id"] = branding["ManagedLoginBrandingId"]

    _ensure_branding()
    ctx.on_cleanup(lambda: _ignore(
        lambda: idp.delete_managed_login_branding(
            UserPoolId=pool_id, ManagedLoginBrandingId=state["branding_id"]
        )
    ))

    n = 10
    branding_id = state["branding_id"]
    calls = [
        (lambda: idp.update_managed_login_branding(
            UserPoolId=pool_id, ManagedLoginBrandingId=branding_id, UseCognitoProvidedValues=True,
        ))
        for _ in range(n)
    ]
    results = _race(calls)
    successes = [r for r in results if r[0]]
    for _, code, message in results:
        if code is None:
            continue
        assert code == "ConcurrentModificationException", f"unexpected error code: {code}"
        assert message == CONFLICT_MESSAGE, (
            f"expected the exact {code} message {CONFLICT_MESSAGE!r}, got {message!r}"
        )
    assert len(successes) >= 1, "expected at least one UpdateManagedLoginBranding racer to win"

    after_update = idp.describe_managed_login_branding(
        UserPoolId=pool_id, ManagedLoginBrandingId=branding_id
    )["ManagedLoginBranding"]
    assert after_update["ManagedLoginBrandingId"] == branding_id, (
        f"expected branding {branding_id!r} still present after the update race, "
        f"got {after_update.get('ManagedLoginBrandingId')!r}"
    )
    assert after_update["UseCognitoProvidedValues"] is True, (
        "expected UseCognitoProvidedValues True after the update race, "
        f"got {after_update.get('UseCognitoProvidedValues')!r}"
    )

    pair_results = _race([
        (lambda: idp.update_managed_login_branding(
            UserPoolId=pool_id, ManagedLoginBrandingId=branding_id, UseCognitoProvidedValues=True,
        )),
        (lambda: idp.delete_managed_login_branding(
            UserPoolId=pool_id, ManagedLoginBrandingId=branding_id,
        )),
    ])
    expected_by_code = {
        "ConcurrentModificationException": CONFLICT_MESSAGE,
        "ResourceNotFoundException": NOT_FOUND_MESSAGE,
    }
    for _, code, message in pair_results:
        if code is None:
            continue
        assert code in expected_by_code, f"unexpected error code on losing side: {code}"
        assert message == expected_by_code[code], (
            f"expected the exact {code} message {expected_by_code[code]!r}, got {message!r}"
        )
    assert any(ok for ok, _, _ in pair_results), "expected one side of the update/delete race to win"

    delete_won = pair_results[1][0]
    try:
        final = idp.describe_managed_login_branding(
            UserPoolId=pool_id, ManagedLoginBrandingId=branding_id
        )["ManagedLoginBranding"]
    except ClientError as e:
        assert delete_won, (
            "delete lost the update/delete race but describe_managed_login_branding failed: "
            f"{e.response['Error']['Code']}"
        )
        assert e.response["Error"]["Code"] == "ResourceNotFoundException", (
            "expected ResourceNotFoundException after delete won the update/delete race, "
            f"got {e.response['Error']['Code']}"
        )
        assert e.response["Error"].get("Message") == NOT_FOUND_MESSAGE, (
            f"expected the exact deleted-branding message {NOT_FOUND_MESSAGE!r}, "
            f"got {e.response['Error'].get('Message')!r}"
        )
    else:
        assert not delete_won, (
            "delete succeeded in the update/delete race but describe_managed_login_branding still "
            "returns the branding"
        )
        assert final["UseCognitoProvidedValues"] is True, (
            "expected UseCognitoProvidedValues True after update won the update/delete race, "
            f"got {final.get('UseCognitoProvidedValues')!r}"
        )


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
            error = e.response["Error"]
            results[i] = (False, error["Code"], error.get("Message"))

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
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_client(ctx, pool_id):
    idp = ctx.client("cognito-idp")
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-client-")
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: _ignore(lambda: idp.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id)))
    return client_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
