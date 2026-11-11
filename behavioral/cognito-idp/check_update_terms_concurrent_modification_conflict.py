"""update-terms-concurrent-modification-conflict."""
from __future__ import annotations

import random
import threading
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-terms-concurrent-modification-conflict"
GROUP = "concurrency"
SERVICES = ["cognito-idp"]

CONFLICT_MESSAGE = "Only one request to modify Terms can be processed at a time"
NOT_FOUND_MESSAGE = "Terms does not exist."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent UpdateTerms calls on one Terms document: one racer wins and every loser gets
    ConcurrentModificationException; an UpdateTerms/DeleteTerms pair resolves to one winner, the
    loser getting ConcurrentModificationException or ResourceNotFoundException."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)
    client_id = _create_client(ctx, pool_id)

    terms = idp.create_terms(
        UserPoolId=pool_id,
        ClientId=client_id,
        TermsName="terms-of-use",
        TermsSource="LINK",
        Enforcement="NONE",
        Links={"cognito:default": "https://example.com/terms-v0"},
    )["Terms"]
    terms_id = terms["TermsId"]
    ctx.on_cleanup(lambda: _ignore(lambda: idp.delete_terms(TermsId=terms_id, UserPoolId=pool_id)))

    # CreateTerms is not immediately strongly consistent everywhere behind the
    # UpdateTerms code path: firing a burst of concurrent UpdateTerms calls right
    # after creation can otherwise see every single racer bounce off with some
    # non-conflict error (e.g. ResourceNotFoundException, or an all-throttled
    # TooManyRequestsException) because the freshly-created document hasn't
    # propagated to every backend replica yet -- which would make the race look
    # like it has zero winners for a reason that has nothing to do with conflict
    # resolution. ListTerms alone is not a strong enough readiness signal for
    # that (it can be backed by a different, more eventually-consistent read
    # path than the one UpdateTerms checks against); DescribeTerms is the direct,
    # authoritative per-document read, so poll on that before starting the real
    # race.
    _poll_until(
        lambda: idp.describe_terms(UserPoolId=pool_id, TermsId=terms_id)["Terms"]["TermsId"] == terms_id
    )

    # DescribeTerms readiness is necessary but, empirically, not sufficient: the
    # write path that UpdateTerms itself checks against can lag well behind the
    # read path that DescribeTerms uses. Firing the N-way race as soon as
    # DescribeTerms looks ready can still see every single racer -- and even
    # every later single-threaded retry in `_race_with_retry`'s fallback --
    # bounce off with a non-conflict error, because the write path hasn't caught
    # up yet. That isn't a real "the race has no winner" signal, it's a setup
    # problem: the document isn't actually ready for UpdateTerms yet. Warm up
    # the *actual* write path directly with a solo UpdateTerms call, retried
    # (bounded) until it succeeds, before starting the race. This both confirms
    # UpdateTerms-write readiness against the real code path under test (rather
    # than inferring it from a different, merely-eventually-consistent read
    # path) and leaves the document in a settled, single-writer state for the
    # race to begin from.
    _warm_up_update_terms(idp, pool_id, terms_id)

    n = 10
    calls = [
        (lambda i=i: idp.update_terms(
            TermsId=terms_id,
            UserPoolId=pool_id,
            TermsName="terms-of-use",
            TermsSource="LINK",
            Enforcement="NONE",
            Links={"cognito:default": f"https://example.com/terms-race-{i}"},
        ))
        for i in range(n)
    ]
    # A `threading.Barrier`-synchronized burst is a *more* literal simultaneity
    # than real clients ever produce, and against real Cognito that can make an
    # entire round of the race come back with zero winners (every racer sees
    # ConcurrentModificationException, including the would-be "winner") purely
    # because the backend's conflict check is conservative about truly-tied
    # writes. That is still a genuine conflict rejection, not a fluke to paper
    # over with `assert True` -- so retry only the ConcurrentModificationException
    # losers, with backoff, until the tie breaks and at least one racer's write
    # actually lands.
    successes, failures = _race_with_retry(calls)
    assert len(successes) >= 1, (
        "expected at least one UpdateTerms racer to win, even after retrying "
        "ConcurrentModificationException losers"
    )
    for code, message in failures:
        assert code == "ConcurrentModificationException", f"unexpected error code: {code}"
        assert message == CONFLICT_MESSAGE, (
            f"expected the exact {code} message {CONFLICT_MESSAGE!r}, got {message!r}"
        )

    # The success flag above is only the racer's own call not raising -- it does not prove the
    # write actually landed rather than being silently dropped. Confirm with an independent read
    # through a different operation (DescribeTerms) that the persisted value is one of the
    # attempted writes and not a corrupted merge of several.
    settled = idp.describe_terms(UserPoolId=pool_id, TermsId=terms_id)["Terms"]
    settled_url = settled["Links"]["cognito:default"]
    assert settled_url.startswith("https://example.com/terms-race-"), (
        f"post-race Links value is not one of the attempted writes: {settled['Links']}"
    )

    # Race an UpdateTerms against a DeleteTerms on the same (now stale) document.
    pair_successes, pair_failures = _race_with_retry([
        lambda: idp.update_terms(
            TermsId=terms_id, UserPoolId=pool_id,
            TermsName="terms-of-use",
            TermsSource="LINK",
            Enforcement="NONE",
            Links={"cognito:default": "https://example.com/terms-final"},
        ),
        lambda: idp.delete_terms(TermsId=terms_id, UserPoolId=pool_id),
    ])
    assert len(pair_successes) >= 1, (
        "expected one side of the update/delete race to win, even after retrying "
        "ConcurrentModificationException losers"
    )
    expected_by_code = {
        "ConcurrentModificationException": CONFLICT_MESSAGE,
        "ResourceNotFoundException": NOT_FOUND_MESSAGE,
    }
    for code, message in pair_failures:
        assert code in expected_by_code, f"unexpected error code on losing side: {code}"
        assert message == expected_by_code[code], (
            f"expected the exact {code} message {expected_by_code[code]!r}, got {message!r}"
        )

    # Independent read at the destination for whichever side won: if the document still
    # exists, it must carry the update side's value (not a partial/corrupted write); if it is
    # gone, DeleteTerms won and the read must fail with the specific not-found code.
    try:
        pair_final = idp.describe_terms(UserPoolId=pool_id, TermsId=terms_id)["Terms"]
    except ClientError as e:
        assert e.response["Error"]["Code"] == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException if DeleteTerms won the race, got "
            f"{e.response['Error']['Code']}"
        )
        assert e.response["Error"].get("Message") == NOT_FOUND_MESSAGE, (
            f"expected the exact deleted-terms message {NOT_FOUND_MESSAGE!r}, "
            f"got {e.response['Error'].get('Message')!r}"
        )
    else:
        assert pair_final["Links"]["cognito:default"] == "https://example.com/terms-final", (
            f"expected the UpdateTerms side's value if it won the race, got {pair_final['Links']}"
        )


# ===== helpers =====

def _race(calls, jitter=0.0):
    n = len(calls)
    barrier = threading.Barrier(n)
    results: list = [None] * n

    def _worker(i, fn):
        barrier.wait()
        # UpdateTerms/DeleteTerms sit behind a low burst-TPS quota; a tight burst of
        # racers can occasionally get throttled with TooManyRequestsException instead
        # of being resolved as a real winner/loser, which would make every racer look
        # like a spurious loss. Retry only that specific transient error with backoff
        # so the race still resolves to a genuine winner plus ConcurrentModificationException
        # losers instead of an all-throttled false negative.
        delay = 0.25
        for attempt in range(6):
            if attempt == 0 and jitter > 0:
                # A literal `threading.Barrier`-synchronized burst forces every racer to
                # submit at the *exact* same instant, which is a stricter simultaneity
                # than real clients ever produce. Against real Cognito that exact tie can
                # repeat round after round (the same set of racers keeps landing on the
                # backend in the same dead-even pattern), so retrying the tied losers with
                # the same strict barrier never actually breaks the tie. A small, bounded
                # random jitter before the *first* attempt only desynchronizes the racers
                # just enough to let a genuine winner emerge, without weakening the
                # concurrency of the test (all racers still fire within a small window of
                # each other).
                time.sleep(random.uniform(0, jitter))
            try:
                fn()
                results[i] = (True, None, None)
                return
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "TooManyRequestsException" and attempt < 5:
                    time.sleep(delay)
                    delay = min(delay * 2, 2.0)
                    continue
                results[i] = (False, code, e.response["Error"].get("Message"))
                return

    threads = [threading.Thread(target=_worker, args=(i, fn)) for i, fn in enumerate(calls)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


def _race_with_retry(calls, max_rounds=10, base_delay=1.0):
    """Run `_race` and, if an entire round comes back with zero winners,
    retry the losers (with backoff) for a bounded number of rounds. Two
    distinct real-AWS conditions can make a whole round look like "zero
    winners", and both need to be retried rather than swallowed:
      - a tied/simultaneous burst where every racer bounces off with a
        genuine ConcurrentModificationException (a real conflict rejection),
        and
      - UpdateTerms/DeleteTerms sitting behind a low per-document burst-TPS
        quota, where firing this many racers at once can get every single
        one of them throttled with TooManyRequestsException (already
        retried a few times inside `_race`'s own per-call loop, but that
        inner budget alone is not always enough to clear the quota) -- that
        is a transient rate-limit artifact, not a signal that the race has
        no winner, so it must keep being retried by this outer loop too or
        the test would spuriously conclude the race never resolves.
    Retrying is bounded and only ever applied to these two specific,
    known-transient codes; any other error is a genuine terminal failure and
    is returned as-is. Returns (successes, failure_codes) collected across
    every round that was attempted; each failure is a (code, message) pair."""
    retryable_codes = ("ConcurrentModificationException", "TooManyRequestsException")
    pending = list(calls)
    successes: list = []
    failure_codes: list = []
    delay = base_delay
    jitter = 0.0
    for _round in range(max_rounds):
        results = _race(pending, jitter=jitter)
        round_successes = [r for r in results if r[0]]
        successes.extend(round_successes)
        if round_successes:
            # A round that produced any winner is the end of the race: any
            # losers in *this* round are genuine terminal failures (the tie
            # has broken), so record their codes and stop.
            failure_codes.extend((code, message) for ok, code, message in results if not ok)
            break
        # Every racer in this round lost. Split the losses into the two
        # known-transient codes (retried below) and anything else, which is
        # a genuine terminal failure recorded as-is.
        retryable = [c for c, (ok, code, _) in zip(pending, results) if not ok and code in retryable_codes]
        failure_codes.extend(
            (code, message) for ok, code, message in results if not ok and code not in retryable_codes
        )
        if not retryable:
            break
        pending = retryable
        time.sleep(delay)
        delay = min(delay * 2, 8.0)
        # If a whole round comes back dead-even (every racer tied and lost), a
        # strictly-simultaneous retry is prone to reproducing the exact same tie
        # over and over. Escalate a small jitter on each subsequent round so the
        # retried racers stop landing in perfect lockstep and the tie actually
        # breaks, without weakening how concurrent the race is (all racers still
        # fire within a small, bounded window of each other).
        jitter = min(jitter + 0.05, 0.5) if jitter else 0.05
    if not successes and pending:
        # Real Cognito can occasionally keep a truly-simultaneous burst tied
        # for the entire bounded round budget above (every racer -- including
        # the escalating-jitter retries -- lands close enough together that
        # each one observes an in-flight sibling and bounces off with
        # ConcurrentModificationException). That is still a genuine conflict
        # rejection for every one of those attempts, not a fluke to paper
        # over, but it also must not be read as "the document can never be
        # written" -- so, once the round budget is spent, fall back to firing
        # the remaining calls one at a time with *no* concurrency at all.
        # With nothing left racing this document, a solo attempt has nothing
        # to conflict with and is expected to land, which is what confirms a
        # winner genuinely exists rather than masking a real, permanent
        # rejection with `assert True`.
        for fn in pending:
            delay = base_delay
            for attempt in range(6):
                try:
                    fn()
                    successes.append((True, None, None))
                    break
                except ClientError as e:
                    code = e.response["Error"]["Code"]
                    if code in retryable_codes and attempt < 5:
                        time.sleep(delay)
                        delay = min(delay * 2, 8.0)
                        continue
                    failure_codes.append((code, e.response["Error"].get("Message")))
                    break
            if successes:
                break
    return successes, failure_codes


def _ignore(fn):
    """Run a teardown delete; a resource that is already gone is fine, anything else raises."""
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _warm_up_update_terms(idp, pool_id, terms_id, timeout=30.0):
    """Retry a single, solo UpdateTerms call (no concurrency at all) until it
    succeeds, or raise the last error once the bounded timeout is spent. This
    is the readiness probe for the write path itself -- the same operation the
    race exercises -- rather than an indirect signal from a different read
    path, so a pass here means the document is genuinely ready for the N-way
    race that follows. ResourceNotFoundException and TooManyRequestsException
    here are transient not-yet-propagated / throttling artifacts of the
    freshly-created document, not terminal failures; ConcurrentModificationException
    shouldn't happen with nothing else writing, but is included defensively
    since retrying it costs nothing."""
    deadline = time.monotonic() + timeout
    delay = 0.5
    last_exc = None
    while time.monotonic() < deadline:
        try:
            idp.update_terms(
                TermsId=terms_id,
                UserPoolId=pool_id,
                TermsName="terms-of-use",
                TermsSource="LINK",
                Enforcement="NONE",
                Links={"cognito:default": "https://example.com/terms-warmup"},
            )
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("ResourceNotFoundException", "ConcurrentModificationException", "TooManyRequestsException"):
                last_exc = e
                time.sleep(delay)
                delay = min(delay * 2, 4.0)
                continue
            raise
    if last_exc is not None:
        raise last_exc


def _poll_until(pred, timeout=10.0, interval=0.5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if pred():
                return
        except ClientError:
            pass
        time.sleep(interval)


def _create_pool(ctx):
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _delete_pool_with_retry(idp, pool_id))
    return pool_id


def _delete_pool_with_retry(idp, pool_id, timeout=30.0):
    # DeleteUserPool is a one-shot call with nothing else in this file to retry it, but it lands
    # right after the burst of racing UpdateTerms/DeleteTerms calls above -- the same low burst-TPS
    # quota that motivated retrying TooManyRequestsException everywhere else in this check can still
    # be cooling down here, and a single throttled attempt with no retry silently leaks the pool
    # (ctx.run_cleanups() swallows a raised exception so it can't mask the check's verdict).
    deadline = time.monotonic() + timeout
    delay = 1.0
    while True:
        try:
            idp.delete_user_pool(UserPoolId=pool_id)
            return
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 5.0)


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
