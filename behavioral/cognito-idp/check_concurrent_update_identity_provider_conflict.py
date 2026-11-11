"""concurrent-update-identity-provider-conflict."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-update-identity-provider-conflict"
GROUP = "concurrency"
SERVICES = ["cognito-idp"]
_CME_MESSAGE = "Only one request to update the identity provider can be processed at a time."


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Racing UpdateIdentityProvider calls on one IdP: at least one succeeds, any loser gets only
    ConcurrentModificationException, and the final AttributeMapping is one successful write."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    provider_name = "Facebook"
    idp.create_identity_provider(
        UserPoolId=pool_id,
        ProviderName=provider_name,
        ProviderType=provider_name,
        ProviderDetails={
            "client_id": "sim2real-fb-client-id",
            "client_secret": "sim2real-fb-client-secret",
            "authorize_scopes": "public_profile",
        },
    )

    n_racers = 8
    # Cognito validates AttributeMapping values against the identity provider's supported
    # source attributes when the target is "username" (e.g. "Invalid attribute mapping. <val>
    # cannot be mapped to username"), so arbitrary per-racer strings are rejected outright
    # regardless of the race. Map to a non-reserved target attribute ("email") instead, which
    # accepts arbitrary source attribute names and still lets us distinguish which racer's
    # write survived the race.
    fns = [
        (lambda i=i: idp.update_identity_provider(
            UserPoolId=pool_id,
            ProviderName=provider_name,
            AttributeMapping={"email": f"racer-{i}"},
        ))
        for i in range(n_racers)
    ]
    results = _race(fns)
    others = [
        (err, msg) for _, err, msg in results if err is not None and not _is_conflict_loser(err)
    ]
    assert not others, f"unexpected errors racing UpdateIdentityProvider: {others}"
    for _, err, msg in results:
        if err is not None:
            assert msg == _CME_MESSAGE, f"{err} message {msg!r}, expected {_CME_MESSAGE!r}"
    successful_values = {f"racer-{i}" for i, (_, err, _msg) in enumerate(results) if err is None}
    assert successful_values, "no UpdateIdentityProvider call succeeded under contention"

    final = idp.describe_identity_provider(
        UserPoolId=pool_id, ProviderName=provider_name
    )["IdentityProvider"]
    mapping_value = final["AttributeMapping"]["email"]
    assert mapping_value in successful_values, (
        f"post-race AttributeMapping {final['AttributeMapping']!r} is not exactly one of the"
        f" successful writes {sorted(successful_values)!r}"
    )


from botocore.exceptions import ClientError


def _call(fn):
    try:
        return fn(), None, None
    except ClientError as e:
        return None, e.response["Error"]["Code"], e.response["Error"].get("Message", "")


def _race(fns):
    with ThreadPoolExecutor(max_workers=len(fns)) as ex:
        futures = [ex.submit(_call, fn) for fn in fns]
        return [f.result() for f in futures]


def _is_conflict_loser(code: str) -> bool:
    """True if `code` is the documented losing-writer outcome for this race."""
    return code == "ConcurrentModificationException"


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
