"""concurrent-set-user-pool-mfa-config-last-writer-wins."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-set-user-pool-mfa-config-last-writer-wins"
GROUP = "concurrency"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent SetUserPoolMfaConfig calls on one pool all succeed, and GetUserPoolMfaConfig then
    returns exactly one of the written configurations, never a mix of them."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    def _mfa_kwargs(optional: bool) -> dict:
        if optional:
            return {
                "MfaConfiguration": "OPTIONAL",
                "SoftwareTokenMfaConfiguration": {"Enabled": True},
            }
        # MfaConfiguration=OFF together with any MFA method configuration (even Enabled=False) is
        # refused ("can't turn off MFA and configure an MFA together"), so OFF omits it.
        return {
            "MfaConfiguration": "OFF",
        }

    n_racers = 8
    fns = [
        (lambda i=i: idp.set_user_pool_mfa_config(
            UserPoolId=pool_id, **_mfa_kwargs(optional=(i % 2 == 0))
        ))
        for i in range(n_racers)
    ]
    results = _race(fns)
    successes = [r for r, err, _msg in results if err is None]
    # Real Cognito performs no optimistic-locking/conflict detection on SetUserPoolMfaConfig, so
    # a "losing" writer under contention (if it errors at all) still only errors for a legitimate
    # conflict-shaped reason -- never with some unrelated/malformed-request error.
    others = [
        (err, msg) for _, err, msg in results if err is not None and not _is_conflict_loser(err, msg)
    ]
    assert not others, f"unexpected errors racing SetUserPoolMfaConfig: {others}"
    assert len(successes) == n_racers, (
        f"real Cognito performs no optimistic locking on SetUserPoolMfaConfig, so every "
        f"racer should have succeeded; only {len(successes)}/{n_racers} did: {results!r}"
    )

    final = idp.get_user_pool_mfa_config(UserPoolId=pool_id)
    assert final["MfaConfiguration"] in ("OPTIONAL", "OFF"), (
        f"post-race MfaConfiguration is not one of the attempted values: {final.get('MfaConfiguration')}"
    )
    if final["MfaConfiguration"] == "OPTIONAL":
        assert final.get("SoftwareTokenMfaConfiguration", {}).get("Enabled") is True, (
            f"OPTIONAL config should report software-token MFA enabled, got {final!r}"
        )
    else:
        # With MfaConfiguration OFF, GetUserPoolMfaConfig omits SoftwareTokenMfaConfiguration
        # (the response is {"MfaConfiguration": "OFF"}), so the field must be absent or falsy.
        assert not final.get("SoftwareTokenMfaConfiguration", {}).get("Enabled"), (
            f"OFF config should report software-token MFA as not enabled, got {final!r}"
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


_CONFLICT_KEYWORDS = ("concurrent", "modif", "conflict", "stale", "changed", "version")


def _is_conflict_loser(code: str, message: str | None) -> bool:
    """True if `code`/`message` represents a legitimate losing-writer outcome for this race:
    ConcurrentModificationException, or an InvalidParameterException whose message reports the
    underlying version/conflict rejection rather than an unrelated malformed-request error."""
    if code == "ConcurrentModificationException":
        return True
    if code == "InvalidParameterException" and message:
        low = message.lower()
        return any(kw in low for kw in _CONFLICT_KEYWORDS)
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
