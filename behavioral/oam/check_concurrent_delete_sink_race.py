"""concurrent-delete-sink-race."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-delete-sink-race"
GROUP = "concurrency"
SERVICES = ["oam"]
_NOT_FOUND = "Resource not found."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:oam-sink")
def run(ctx) -> None:
    """N concurrent DeleteSink calls on the same sink: exactly one wins, the rest get NotFound."""
    oam = ctx.client("oam")

    sink_name = ctx.unique_name("sim2real-oam-sink-")
    sink = _create_sink_retrying(oam, sink_name, sink_tags={"sim2real": CHECK})
    sink_arn = sink["Arn"]
    ctx.on_cleanup(lambda: _delete_sink_ignore_missing(oam, sink_arn))

    n_racers = 6

    def attempt(_):
        try:
            oam.delete_sink(Identifier=sink_arn)
            return ("ok", None)
        except ClientError as exc:
            error = exc.response["Error"]
            return ("err", (error["Code"], error.get("Message")))

    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        results = list(pool.map(attempt, range(n_racers)))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "err"]

    assert len(successes) == 1, f"expected exactly one delete to win, got {results}"
    assert len(failures) == n_racers - 1, (
        f"expected {n_racers - 1} losing deletes, got {len(failures)} in {results}"
    )
    for _, (code, message) in failures:
        assert code == "ResourceNotFoundException", f"unexpected loser code: {code}"
        assert message == _NOT_FOUND, f"unexpected loser message: {message!r}"

    # the sink is genuinely gone -- not left in some half-deleted state.
    get_code, get_code_message = _error(lambda: oam.get_sink(Identifier=sink_arn))
    assert get_code == "ResourceNotFoundException", f"got {get_code!r}"
    assert get_code_message == _NOT_FOUND, f"got message {get_code_message!r}"


def _error(fn):
    """Call fn(), which must fail; return its botocore error (code, message). An unexpected
    SUCCESS raises, so a target that accepts what AWS refuses is never read as a mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_sink_retrying(oam, name, timeout_s=90.0, interval_s=3.0, sink_tags=None):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return oam.create_sink(Name=name, Tags=sink_tags or {})
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ServiceQuotaExceededException":
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _delete_sink_ignore_missing(oam, arn):
    try:
        oam.delete_sink(Identifier=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

