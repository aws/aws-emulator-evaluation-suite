"""ssm-concurrent-overwrites-keep-every-version-byte-exact-and-both-read-paths-agree."""
from __future__ import annotations

import concurrent.futures
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ssm-concurrent-overwrites-keep-every-version-byte-exact-and-both-read-paths-agree"
GROUP = 'concurrency'
SERVICES = ['ssm']

_THREADS = 8
_INITIAL = "initial"
_THROTTLE = ("TooManyUpdates", "ThrottlingException")


# Concurrent PutParameter on ONE name is throttled with TooManyUpdates by design, so the
# retry lets the invariant cover all eight writers instead of whichever happened to win.
def _param_name(ctx, suffix=""):
    # SSM requires a leading '/' for any hierarchical (slash-containing) name.
    return "/" + ctx.unique_name("sim2real-behav-" + suffix)


def _track_parameter(ctx, ssm, name):
    ctx.on_cleanup(lambda: _call_with_retry(lambda: ssm.delete_parameter(Name=name)))
    return name


def _call_with_retry(fn, retries=30, delay=1.0):
    last = None
    for _ in range(retries):
        try:
            return fn()
        except ClientError as exc:
            last = exc
            if exc.response.get("Error", {}).get("Code") in _THROTTLE:
                time.sleep(delay)
                continue
            raise
    raise last


def _history(ssm, name):
    """Every version record for `name`, fully paginated, sorted by version."""
    rows = (
        ssm.get_paginator("get_parameter_history")
        .paginate(Name=name)
        .build_full_result()["Parameters"]
    )
    return sorted(rows, key=lambda r: r["Version"])


@tags("axis:happy-path", "concern:representation", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """Eight concurrent overwrites of one parameter consume versions 2..9, every stored version
    holds bytes some writer sent, and the `name:N` selector and GetParameterHistory agree on each
    version.
    """

    ssm = ctx.client("ssm")

    name = _param_name(ctx, "conc-")
    _track_parameter(ctx, ssm, name)
    first = ssm.put_parameter(Name=name, Value=_INITIAL, Type="String")
    assert first["Version"] == 1, f"the first PutParameter must mint Version 1, got {first!r}"

    written = {i: f"thread-{i:02d}-value" for i in range(_THREADS)}
    sent = set(written.values())

    def _write(i):
        resp = _call_with_retry(
            lambda: ssm.put_parameter(
                Name=name, Value=written[i], Type="String", Overwrite=True
            )
        )
        return i, resp["Version"]

    errors = []
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=_THREADS) as ex:
        futures = [ex.submit(_write, i) for i in range(_THREADS)]
        for fut in futures:
            try:
                results.append(fut.result())
            except ClientError as exc:
                errors.append(exc.response.get("Error", {}).get("Code"))

    assert len(results) == _THREADS, (
        f"{len(results)} of {_THREADS} concurrent overwrites succeeded even with a bounded "
        f"throttle retry; unrecovered codes {errors!r}"
    )

    # --- every successful write consumes exactly one version -----------------
    versions = sorted(v for _, v in results)
    assert len(set(versions)) == _THREADS, (
        f"two writers were handed the same version: {versions!r}"
    )
    assert versions == list(range(2, 2 + _THREADS)), (
        "the eight overwrites must consume versions 2..9 with no gaps and without reusing "
        f"version 1; got {versions!r}"
    )

    # --- the value ledger: nine versions, every byte accounted for -----------
    # Under contention a returned Version is a counter reservation, not a receipt for that
    # writer's bytes, and a value can be stored twice while another is lost, so only
    # membership in the sent set is asserted.
    history = _history(ssm, name)
    assert [h["Version"] for h in history] == list(range(1, 2 + _THREADS)), (
        f"the history must hold versions 1..{1 + _THREADS}, got "
        f"{[h['Version'] for h in history]!r}"
    )
    assert history[0]["Value"] == _INITIAL, (
        f"version 1 must still hold the pre-contention value {_INITIAL!r}, got "
        f"{history[0]['Value']!r} — a concurrent overwrite rewrote an existing version"
    )
    allowed = sent | {_INITIAL}
    for h in history:
        assert h["Value"] in allowed, (
            f"version {h['Version']} holds {h['Value']!r}, which no writer sent and which is "
            f"not {_INITIAL!r} — the value was blended, truncated or invented. Every stored "
            f"byte must come from {sorted(allowed)!r}"
        )
    # Versions 2..9 must all hold a CONCURRENT writer's value, never the initial
    # one: the initial value may not be re-committed at a later version.
    for h in history[1:]:
        assert h["Value"] in sent, (
            f"version {h['Version']} holds {h['Value']!r}; versions 2..{1 + _THREADS} were "
            "all minted by the concurrent writers, so none may hold the initial value"
        )

    # --- the two read paths must agree, one version at a time ---------------
    for h in history:
        pinned = ssm.get_parameter(Name=f"{name}:{h['Version']}")["Parameter"]
        assert pinned["Version"] == h["Version"], (
            f"selector ':{h['Version']}' resolved Version {pinned['Version']!r}"
        )
        assert pinned["Value"] == h["Value"], (
            f"GetParameter(':{h['Version']}') returned {pinned['Value']!r} but "
            f"GetParameterHistory records {h['Value']!r} for that version — the two read "
            "paths disagree, so one of them is synthesised"
        )

    # --- the unselected read settles on the highest version -----------------
    highest = max(versions)
    current = ssm.get_parameter(Name=name)["Parameter"]
    assert current["Version"] == highest, (
        f"the unselected read must settle on version {highest}, got {current['Version']!r}"
    )
    top = [h for h in history if h["Version"] == highest]
    assert len(top) == 1, f"version {highest} appears {len(top)} times in the history"
    assert current["Value"] == top[0]["Value"], (
        f"the current value must be what version {highest} holds ({top[0]['Value']!r}), got "
        f"{current['Value']!r}"
    )
    assert current["Value"] in sent, (
        f"the surviving value must be one a concurrent writer sent, not {_INITIAL!r} or "
        f"anything else; got {current['Value']!r}"
    )

    # --- a version past the last one minted must not resolve ----------------
    # Bounds the ledger from above: eight successful overwrites minted exactly
    # eight versions, so there is no version 10 to read.
    beyond = highest + 1
    try:
        stray = ssm.get_parameter(Name=f"{name}:{beyond}")["Parameter"]
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        assert code == "ParameterVersionNotFound", (
            f"reading one version past the last one minted must raise "
            f"ParameterVersionNotFound, got {code!r}"
        )
        message = exc.response.get("Error", {}).get("Message", "")
        assert message == (
            f"Systems Manager could not find version {beyond} of {name.lstrip('/')}. "
            "Verify the version and try again."
        ), message
    else:
        raise AssertionError(
            f"version {beyond} resolved to {stray!r} although only {_THREADS} overwrites "
            "succeeded, so the version counter ran ahead of the writes"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
