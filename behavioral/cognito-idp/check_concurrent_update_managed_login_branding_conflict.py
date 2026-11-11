"""concurrent-update-managed-login-branding-conflict."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-update-managed-login-branding-conflict"
GROUP = "concurrency"
SERVICES = ["cognito-idp"]


CONFLICT_MESSAGE = "Only one request to modify a ManagedLoginBranding can be processed at a time"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Racing UpdateManagedLoginBranding calls on one style: at least one succeeds, any loser gets
    only ConcurrentModificationException with its exact message, and the style stays readable."""
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

    n_racers = 8
    fns = [
        (lambda: idp.update_managed_login_branding(
            UserPoolId=pool_id,
            ManagedLoginBrandingId=branding_id,
            UseCognitoProvidedValues=True,
        ))
        for _ in range(n_racers)
    ]
    results = _race(fns)
    successes = [r for r, err, _msg in results if err is None]
    for _, err, msg in results:
        if err is None:
            continue
        assert err == "ConcurrentModificationException", f"unexpected errors racing UpdateManagedLoginBranding: {err}"
        assert msg == CONFLICT_MESSAGE, f"expected the exact {err} message {CONFLICT_MESSAGE!r}, got {msg!r}"
    assert len(successes) >= 1, "no UpdateManagedLoginBranding call succeeded under contention"

    final = idp.describe_managed_login_branding(
        UserPoolId=pool_id, ManagedLoginBrandingId=branding_id
    )["ManagedLoginBranding"]
    assert final["ManagedLoginBrandingId"] == branding_id
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
