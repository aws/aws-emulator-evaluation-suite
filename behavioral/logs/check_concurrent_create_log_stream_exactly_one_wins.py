"""concurrent-create-log-stream-exactly-one-wins."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

CHECK = "concurrent-create-log-stream-exactly-one-wins"
GROUP = "error-semantics"
SERVICES = ["logs"]

from behavioral_harness import tags

_RACERS = 8


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateLogStream calls with the same name create exactly one stream: one call succeeds and
    every other gets ResourceAlreadyExistsException."""
    logs = ctx.client("logs")

    log_group = ctx.unique_name("sim2real-racelogstream-lg-")
    logs.create_log_group(logGroupName=log_group, tags={"sim2real": CHECK, "sim2real:managed": "true"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))

    stream_name = ctx.unique_name("sim2real-racelogstream-")

    def _attempt():
        try:
            logs.create_log_stream(logGroupName=log_group, logStreamName=stream_name)
            return ("ok", None)
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code") if hasattr(exc, "response") else None
            return ("error", code)

    with ThreadPoolExecutor(max_workers=_RACERS) as pool:
        futures = [pool.submit(_attempt) for _ in range(_RACERS)]
        outcomes = [f.result() for f in as_completed(futures)]

    successes = [o for o in outcomes if o[0] == "ok"]
    failures = [o for o in outcomes if o[0] == "error"]

    assert len(successes) == 1, f"expected exactly 1 winner among {_RACERS} racers, got {len(successes)}"
    assert len(failures) == _RACERS - 1, f"expected {_RACERS - 1} losers, got {len(failures)}"
    bad_codes = {code for _, code in failures if code != "ResourceAlreadyExistsException"}
    assert not bad_codes, f"losing racers got unexpected error codes: {bad_codes}"

    streams = logs.describe_log_streams(logGroupName=log_group, logStreamNamePrefix=stream_name)["logStreams"]
    assert len(streams) == 1, f"expected exactly one log stream to exist, found {len(streams)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
