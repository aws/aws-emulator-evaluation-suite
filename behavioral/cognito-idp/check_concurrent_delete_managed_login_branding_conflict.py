"""concurrent-delete-managed-login-branding-conflict."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-delete-managed-login-branding-conflict"
GROUP = "concurrency"
SERVICES = ["cognito-idp"]


CONFLICT_MESSAGE = "Only one request to modify a ManagedLoginBranding can be processed at a time"
NOT_FOUND_MESSAGE = "ManagedLoginBranding does not exist."


@tags("axis:happy-path", "cap:c1", "plane:control")
def run(ctx) -> None:
    """DeleteManagedLoginBranding racing UpdateManagedLoginBranding on one style: losers get only
    ConcurrentModificationException or ResourceNotFoundException with their exact messages, and the
    style is gone if any delete succeeded, otherwise intact."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-client-")
    )["UserPoolClient"]["ClientId"]

    branding_id = idp.create_managed_login_branding(
        UserPoolId=pool_id, ClientId=client_id, UseCognitoProvidedValues=True
    )["ManagedLoginBranding"]["ManagedLoginBrandingId"]

    n_deletes = 3
    fns = [
        (lambda: idp.delete_managed_login_branding(
            UserPoolId=pool_id, ManagedLoginBrandingId=branding_id
        ))
        for _ in range(n_deletes)
    ] + [
        (lambda: idp.update_managed_login_branding(
            UserPoolId=pool_id, ManagedLoginBrandingId=branding_id, UseCognitoProvidedValues=True
        ))
        for _ in range(5)
    ]
    results = _race(fns)
    expected_by_code = {
        "ConcurrentModificationException": CONFLICT_MESSAGE,
        "ResourceNotFoundException": NOT_FOUND_MESSAGE,
    }
    for _, code, message in results:
        if code is None:
            continue
        assert code in expected_by_code, f"unexpected error racing delete/update managed login branding: {code}"
        assert message == expected_by_code[code], (
            f"expected the exact {code} message {expected_by_code[code]!r}, got {message!r}"
        )
    assert any(code is None for _, code, _ in results), "no delete/update call succeeded under contention"
    delete_won = any(code is None for _, code, _ in results[:n_deletes])

    try:
        final = idp.describe_managed_login_branding(
            UserPoolId=pool_id, ManagedLoginBrandingId=branding_id
        )["ManagedLoginBranding"]
    except ClientError as e:
        assert delete_won, (
            "no DeleteManagedLoginBranding succeeded but the branding is unreadable: "
            f"{e.response['Error']['Code']}"
        )
        assert e.response["Error"]["Code"] == "ResourceNotFoundException", (
            "managed login branding left in an unexpected error state after the race"
        )
        assert e.response["Error"].get("Message") == NOT_FOUND_MESSAGE, (
            f"expected the exact ResourceNotFoundException message, got {e.response['Error'].get('Message')!r}"
        )
    else:
        assert not delete_won, "a DeleteManagedLoginBranding succeeded but the branding is still readable"
        assert final["UseCognitoProvidedValues"] is True

from botocore.exceptions import ClientError


def _call(fn):
    try:
        return fn(), None, None
    except ClientError as e:
        return None, e.response["Error"]["Code"], e.response["Error"].get("Message")


def _race(fns):
    with ThreadPoolExecutor(max_workers=len(fns)) as ex:
        futures = [ex.submit(_call, fn) for fn in fns]
        return [f.result() for f in futures]


def _wait_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
