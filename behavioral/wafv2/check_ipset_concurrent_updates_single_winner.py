"""ipset-concurrent-updates-single-winner."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "ipset-concurrent-updates-single-winner"
GROUP = 'concurrency'
SERVICES = ['wafv2']


SCOPE = "REGIONAL"
_STALE_LOCK = (
    "AWS WAF couldn\u2019t save your changes because someone changed the resource after you "
    "started to edit it. Reapply your changes."
)

_TRANSIENT_CODES = frozenset(
    {"ThrottlingException", "WAFUnavailableEntityException", "WAFInternalErrorException"}
)

def _retry_transient(fn, attempts=12, delay=6.0, codes=None):
    """Call fn, retrying WAFv2's transient control-plane errors (throttling /
    just-created-entity-not-yet-resolvable)."""
    retryable = codes or _TRANSIENT_CODES
    last_exc = None
    for attempt in range(attempts):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - inspect error code
            code = ""
            resp = getattr(exc, "response", None)
            if isinstance(resp, dict):
                code = resp.get("Error", {}).get("Code", "")
            if code not in retryable:
                raise
            last_exc = exc
            if attempt == attempts - 1:
                break
            time.sleep(delay)
    raise last_exc

_TEARDOWN_RETRY_CODES = (
    "WAFAssociatedItemException", "WAFOptimisticLockException", "WAFUnavailableEntityException"
)

def _delete_locked(w, kind, name, scope, id_):
    """Refresh the LockToken then delete (WAFv2 delete_* require the current token)."""
    getter = getattr(w, f"get_{kind}")
    deleter = getattr(w, f"delete_{kind}")
    deadline = time.monotonic() + 25.0
    while True:
        try:
            lt = getter(Name=name, Scope=scope, Id=id_)["LockToken"]
            deleter(Name=name, Scope=scope, Id=id_, LockToken=lt)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "WAFNonexistentItemException":
                return
            # A reference or lock-token race still settling is retried; anything else raises.
            if code not in _TEARDOWN_RETRY_CODES or time.monotonic() >= deadline:
                raise
        time.sleep(2)

def _create_ipset(ctx, w, name=None, addresses=None, scope=SCOPE):
    """Create an IPSet (registered for teardown). Returns the Summary dict."""
    name = name or ctx.unique_name("sim2real-behav-waf-ips-")
    addresses = addresses if addresses is not None else ["10.0.0.0/8"]
    summary = _retry_transient(
        lambda: w.create_ip_set(
            Name=name, Scope=scope, IPAddressVersion="IPV4", Addresses=addresses
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "ip_set", name, scope, summary["Id"]))
    return summary


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Of 5 concurrent UpdateIPSet calls with the same LockToken, exactly one succeeds and every other
    fails with WAFOptimisticLockException and the exact message; GetIPSet returns the winner's
    addresses and NextLockToken.
    """
    w = ctx.client("wafv2")
    summary = _create_ipset(ctx, w, addresses=["10.0.0.0/8"])
    got = w.get_ip_set(Name=summary["Name"], Scope=SCOPE, Id=summary["Id"])
    shared_token = got["LockToken"]

    n = 5
    racer_addresses = {i: [f"10.{i}.0.0/16"] for i in range(n)}

    def racer(i):
        return w.update_ip_set(
            Name=summary["Name"],
            Scope=SCOPE,
            Id=summary["Id"],
            Addresses=racer_addresses[i],
            LockToken=shared_token,
        )

    outcomes = []
    with ThreadPoolExecutor(max_workers=n) as pool:
        futures = {pool.submit(racer, i): i for i in range(n)}
        for fut, i in futures.items():
            try:
                outcomes.append(("ok", i, fut.result()))
            except ClientError as exc:
                error = exc.response.get("Error", {})
                outcomes.append(("err", i, (error.get("Code", ""), error.get("Message"))))

    winners = [(i, resp) for kind, i, resp in outcomes if kind == "ok"]
    error_codes = [err[0] for kind, _, err in outcomes if kind == "err"]
    error_messages = [err[1] for kind, _, err in outcomes if kind == "err"]

    assert len(winners) == 1, (
        f"expected exactly 1 winner under a shared LockToken, got "
        f"{len(winners)} (codes={error_codes})"
    )
    assert len(error_codes) == n - 1, (
        f"expected {n - 1} losers, got {len(error_codes)} (codes={error_codes})"
    )
    assert all(c == "WAFOptimisticLockException" for c in error_codes), (
        f"expected every loser to fail with WAFOptimisticLockException, got {error_codes}"
    )
    assert all(m == _STALE_LOCK for m in error_messages), error_messages

    winner_index, winner_resp = winners[0]
    final = w.get_ip_set(Name=summary["Name"], Scope=SCOPE, Id=summary["Id"])
    assert final["IPSet"]["Addresses"] == racer_addresses[winner_index], (
        "the IPSet must end up holding exactly the winning racer's addresses, "
        f"expected {racer_addresses[winner_index]}, got {final['IPSet']['Addresses']}"
    )
    assert final["LockToken"] == winner_resp["NextLockToken"], (
        "final LockToken must equal the winner's own NextLockToken, "
        f"expected {winner_resp['NextLockToken']!r}, got {final['LockToken']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
