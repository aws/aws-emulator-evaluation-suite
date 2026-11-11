"""concurrent-update-channel-namespace."""
from __future__ import annotations

import concurrent.futures
import re

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _run_concurrent(fns, *, timeout_s=60):
    """Run callables in parallel; return results in submission order — each entry is the callable's
    return value or the Exception it raised (captured, NOT re-raised)."""
    results = [None] * len(fns)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
                idx = future_to_idx[fut]
                try:
                    results[idx] = fut.result()
                except Exception as exc:  # noqa: BLE001 — captured for the caller to assert on
                    results[idx] = exc
        except concurrent.futures.TimeoutError:
            for pending, i in future_to_idx.items():
                if not pending.done():
                    results[i] = concurrent.futures.TimeoutError(f"call did not finish within {timeout_s}s")
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results

def _successes(results):
    return sum(1 for r in results if not isinstance(r, BaseException))

def _error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get("Error", {}).get("Code"))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes

def _error_pairs(results):
    """(code, message) of every racer that failed, in submission order."""
    pairs = []
    for r in results:
        if isinstance(r, ClientError):
            err = r.response.get("Error", {})
            pairs.append((err.get("Code"), err.get("Message")))
        elif isinstance(r, BaseException):
            pairs.append((type(r).__name__, str(r)))
    return pairs

def _delete_if_present(fn):
    """Teardown for a resource the check's own delete race may already have removed."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise

def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected success
    raises, so an emulator that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

def _ns_name(raw):
    """Channel-namespace name: ([A-Za-z0-9](?:[A-Za-z0-9-]{0,48}[A-Za-z0-9])?), <=50 chars."""
    cleaned = re.sub(r"[^0-9A-Za-z-]", "-", raw)
    cleaned = re.sub(r"-+", "-", cleaned).strip("-")
    if len(cleaned) > 50:
        cleaned = cleaned[:50]
    cleaned = cleaned.strip("-")
    if not cleaned or not cleaned[0].isalnum():
        cleaned = "n" + cleaned
    return cleaned

CHECK = "concurrent-update-channel-namespace"
GROUP = 'concurrency'
SERVICES = ['appsync']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent writers to one ChannelNamespace keep one racer's exact payload and fail losers with
    ConcurrentModificationException; concurrent deletes have a winner, losers 404, the id stays dead."""
    svc = ctx.client("appsync")
    api = svc.create_api(
        name=ctx.unique_name("sim2real-behav-appsync-eventapi-"),
        eventConfig={
            "authProviders": [{"authType": "API_KEY"}, {"authType": "AWS_IAM"}],
            "connectionAuthModes": [{"authType": "API_KEY"}],
            "defaultPublishAuthModes": [{"authType": "API_KEY"}],
            "defaultSubscribeAuthModes": [{"authType": "API_KEY"}],
        },
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["api"]
    ctx.on_cleanup(lambda _a=api: svc.delete_api(apiId=_a["apiId"]))
    api_id = api["apiId"]
    name = _ns_name(ctx.unique_name("sim2real-behav-chan-"))
    svc.create_channel_namespace(
        apiId=api_id,
        name=name,
        subscribeAuthModes=[{"authType": "API_KEY"}],
        publishAuthModes=[{"authType": "API_KEY"}],
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )
    ctx.on_cleanup(lambda: _delete_if_present(lambda: svc.delete_channel_namespace(apiId=api_id, name=name)))
    racers = 5

    def update_attempt(i):
        return svc.update_channel_namespace(
            apiId=api_id,
            name=name,
            subscribeAuthModes=[{"authType": "API_KEY"}],
            publishAuthModes=[{"authType": "API_KEY"}],
            codeHandlers=f"export function onPublish(ctx) {{ return ctx.events; }} // race-{i}",
        )

    results = _run_concurrent([lambda i=i: update_attempt(i) for i in range(racers)])
    successes = _successes(results)
    codes = _error_codes(results)
    assert successes >= 1, f"expected at least one UpdateChannelNamespace racer to win, got results={results!r}"
    assert successes + len(codes) == racers, (
        f"every UpdateChannelNamespace racer must resolve to either a success or an error, got {results!r}"
    )
    for code, message in _error_pairs(results):
        assert code == "ConcurrentModificationException", (
            f"expected every losing UpdateChannelNamespace racer to fail with "
            f"ConcurrentModificationException, got {code} {message!r} (all codes: {codes!r})"
        )

    expected_handlers = {
        f"export function onPublish(ctx) {{ return ctx.events; }} // race-{i}" for i in range(racers)
    }
    got = svc.get_channel_namespace(apiId=api_id, name=name)["channelNamespace"]
    assert got.get("codeHandlers") in expected_handlers, (
        f"expected the persisted codeHandlers to be exactly one racer's payload "
        f"(one of {sorted(expected_handlers)!r}), got {got.get('codeHandlers')!r}"
    )

    del_results = _run_concurrent(
        [lambda: svc.delete_channel_namespace(apiId=api_id, name=name) for _ in range(3)]
    )
    # More than one concurrent DeleteChannelNamespace can succeed; every loser finds the
    # namespace gone and gets the empty-message NotFoundException.
    del_successes = _successes(del_results)
    assert del_successes >= 1, f"expected at least one DeleteChannelNamespace racer to win, got {del_results!r}"
    for code, message in _error_pairs(del_results):
        assert (code, message) == ("NotFoundException", ""), (
            f"expected every losing DeleteChannelNamespace racer to fail with the empty-message "
            f"NotFoundException, got {code} {message!r}"
        )

    code_after, message_after = _error(lambda: svc.get_channel_namespace(apiId=api_id, name=name))
    assert code_after == "NotFoundException", (
        f"expected NotFoundException from GetChannelNamespace after the delete race settled, got {code_after}"
    )
    assert message_after == "Channel namespace not found.", (
        f"expected the exact NotFound message from GetChannelNamespace, got {message_after!r}"
    )

    # AWS sends this NotFoundException with an empty message; the exact empty string is graded.
    mutate_after, mutate_message = _error(
        lambda: svc.update_channel_namespace(
            apiId=api_id,
            name=name,
            subscribeAuthModes=[{"authType": "API_KEY"}],
            publishAuthModes=[{"authType": "API_KEY"}],
        )
    )
    assert mutate_after == "NotFoundException", (
        f"expected UpdateChannelNamespace against the deleted namespace to also fail with "
        f"NotFoundException, got {mutate_after}"
    )
    assert mutate_message == "", (
        f"expected the empty NotFound message from UpdateChannelNamespace, got {mutate_message!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
