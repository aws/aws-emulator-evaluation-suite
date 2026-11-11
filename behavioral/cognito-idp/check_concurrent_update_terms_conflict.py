"""concurrent-update-terms-conflict."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-update-terms-conflict"
GROUP = "concurrency"
SERVICES = ["cognito-idp"]


CONFLICT_MESSAGE = "Only one request to modify Terms can be processed at a time"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Racing UpdateTerms calls on one terms document: at least one succeeds, any loser gets only
    ConcurrentModificationException (exact message) or a conflict InvalidParameterException, and the
    final Links value is exactly one successful write."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-client-")
    )["UserPoolClient"]["ClientId"]

    terms_id = idp.create_terms(
        UserPoolId=pool_id,
        ClientId=client_id,
        TermsName="terms-of-use",
        TermsSource="LINK",
        Enforcement="NONE",
        Links={"cognito:default": "https://example.com/terms-initial"},
    )["Terms"]["TermsId"]

    # A freshly created Terms document is not guaranteed to have propagated to the
    # backend replica UpdateTerms itself reads from yet; racing immediately can bounce
    # every racer off with ResourceNotFoundException, which has nothing to do with
    # conflict resolution. Wait on the same read UpdateTerms depends on before racing it.
    _wait_until(
        lambda: _probe_terms(idp, pool_id, terms_id),
        lambda t: t is not None,
        timeout_s=_bounded(ctx, 10.0, reserve_s=30.0),
        interval_s=0.5,
    )

    n_racers = 8
    urls = [f"https://example.com/terms-{i}" for i in range(n_racers)]
    fns = [
        (lambda url=url: idp.update_terms(
            UserPoolId=pool_id,
            TermsId=terms_id,
            TermsName="terms-of-use",
            TermsSource="LINK",
            Enforcement="NONE",
            Links={"cognito:default": url},
        ))
        for url in urls
    ]
    results = _race(fns)
    others = [
        (err, msg) for _, err, msg in results if err is not None and not _is_conflict_loser(err, msg)
    ]
    assert not others, f"unexpected errors racing UpdateTerms: {others}"
    for _, err, msg in results:
        if err == "ConcurrentModificationException":
            assert msg == CONFLICT_MESSAGE, f"expected the exact {err} message {CONFLICT_MESSAGE!r}, got {msg!r}"
    successful_urls = {urls[i] for i, (_, err, _msg) in enumerate(results) if err is None}
    assert successful_urls, "no UpdateTerms call succeeded under contention"

    final = idp.describe_terms(UserPoolId=pool_id, TermsId=terms_id)["Terms"]
    assert final["Links"] in [{"cognito:default": url} for url in successful_urls], (
        f"post-race Links {final['Links']!r} is not one successful write {sorted(successful_urls)!r}"
    )


from botocore.exceptions import ClientError


def _call(fn):
    # UpdateTerms sits behind a low burst-TPS quota; racing 8 calls at once can get one
    # or more throttled with TooManyRequestsException, which is a transient rate-limit
    # artifact and not a conflict-loser outcome. Retry that specific code with backoff
    # so a throttle does not get misread as an unexpected/unrelated error.
    delay = 0.25
    for attempt in range(6):
        try:
            return fn(), None, None
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "TooManyRequestsException" and attempt < 5:
                time.sleep(delay)
                delay = min(delay * 2, 2.0)
                continue
            return None, code, e.response["Error"].get("Message", "")


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


def _probe_terms(idp, pool_id, terms_id):
    try:
        terms = idp.describe_terms(UserPoolId=pool_id, TermsId=terms_id)["Terms"]
    except ClientError:
        return None
    return terms if terms["TermsId"] == terms_id else None


def _bounded(ctx, wanted_s: float, *, reserve_s: float) -> float:
    """`wanted_s`, cut so `reserve_s` of the check's budget is left for what follows."""
    left = ctx.time_left()
    return wanted_s if left is None else max(1.0, min(wanted_s, left - reserve_s))


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
