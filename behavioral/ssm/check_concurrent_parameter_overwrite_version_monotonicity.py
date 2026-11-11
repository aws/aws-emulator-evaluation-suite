"""concurrent-parameter-overwrite-version-monotonicity."""
from __future__ import annotations

import concurrent.futures
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-parameter-overwrite-version-monotonicity"
GROUP = 'state-machine'
SERVICES = ['ssm']

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Concurrent PutParameter(Overwrite=True) calls each consume exactly one version: k successes
    from version 1 return exactly {2..k+1}, and GetParameter settles on the highest version."""

    ssm = ctx.client("ssm")

    def _param_name(suffix=""):
        # SSM requires a leading '/' for any hierarchical (slash-containing) name.
        return "/" + ctx.unique_name("sim2real-behav-" + suffix)

    def _track_parameter(name):
        ctx.on_cleanup(lambda: ssm.delete_parameter(Name=name))
        return name

    def _run_parallel(calls):
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(calls)) as ex:
            futures = [ex.submit(c) for c in calls]
            for f in futures:
                try:
                    results.append((True, f.result()))
                except ClientError as exc:
                    err = exc.response.get("Error", {})
                    results.append((False, (err.get("Code"), err.get("Message"))))
        return results

    def _retry_throttled(fn, attempts=6, base_delay=0.5):
        # Throttling says nothing about the race, so each racer retries it away.
        for attempt in range(attempts):
            try:
                return fn()
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "ThrottlingException":
                    raise
                if attempt == attempts - 1:
                    raise AssertionError(
                        f"racer still throttled after {attempts - 1} retries: {exc}"
                    ) from exc
                time.sleep(base_delay * (2 ** attempt))

    name = _param_name("probe-param-concurrent-")
    _track_parameter(name)
    ssm.put_parameter(
        Name=name,
        Value="v1",
        Type="String",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )

    n = 6

    def make_call(i):
        def _call():
            resp = _retry_throttled(
                lambda: ssm.put_parameter(
                    Name=name, Value=f"concurrent-{i}", Type="String", Overwrite=True
                )
            )
            return resp["Version"]

        return _call

    results = _run_parallel([make_call(i) for i in range(n)])
    versions = sorted(value for ok, value in results if ok)
    failures = [value for ok, value in results if not ok]

    assert versions, f"no concurrent overwrite succeeded: {results}"
    # A racer that loses the overwrite is refused, never silently dropped.
    for code, message in failures:
        assert code == "TooManyUpdates", f"unexpected refusal of a losing racer: {failures}"
        assert message == "", f"unexpected TooManyUpdates message: {failures}"

    expected = list(range(2, 2 + len(versions)))
    assert versions == expected, (
        f"versions must be dense and unique; got {versions}, expected {expected}"
    )

    final = ssm.get_parameter(Name=name)["Parameter"]
    assert final["Version"] == versions[-1], (final, versions)

    history = ssm.get_parameter_history(Name=name)["Parameters"]
    hist_versions = sorted(p["Version"] for p in history)
    assert hist_versions == [1] + expected, hist_versions


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
