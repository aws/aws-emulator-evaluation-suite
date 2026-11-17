"""update-otel-enrichment-replaces-filters-wholesale."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-otel-enrichment-replaces-filters-wholesale"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]

_NAMESPACE_A = "Sim2RealProbe/CloudWatchRMC-A"
_NAMESPACE_B = "Sim2RealProbe/CloudWatchRMC-B"


def _retrying(fn, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            throttled = exc.response.get("Error", {}).get("Code") == "ThrottlingException"
            if not throttled or time.monotonic() > deadline:
                raise
            time.sleep(interval_s)


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:representation",
    "plane:control",
    "resource:account-singleton:cloudwatch-otel-enrichment",
)
def run(ctx) -> None:
    """UpdateOTelEnrichment replaces both IncludeFilters and ExcludeFilters as a pair: a request
    naming only IncludeFilters also clears a previously stored ExcludeFilters."""
    cw = ctx.client("cloudwatch")

    original = _retrying(lambda: cw.get_otel_enrichment())

    def _restore() -> None:
        if original["Status"] == "Running":
            _retrying(
                lambda: cw.start_otel_enrichment(
                    IncludeFilters=original.get("IncludeFilters", []),
                    ExcludeFilters=original.get("ExcludeFilters", []),
                )
            )
        else:
            _retrying(lambda: cw.stop_otel_enrichment())

    ctx.on_cleanup(_restore)

    _retrying(
        lambda: cw.start_otel_enrichment(
            IncludeFilters=[{"Namespace": _NAMESPACE_A}],
            ExcludeFilters=[{"Namespace": _NAMESPACE_B}],
        )
    )
    started = _retrying(lambda: cw.get_otel_enrichment())
    assert started["IncludeFilters"] == [{"Namespace": _NAMESPACE_A}], (
        f"StartOTelEnrichment's IncludeFilters did not stick, got {started['IncludeFilters']!r}"
    )
    assert started["ExcludeFilters"] == [{"Namespace": _NAMESPACE_B}], (
        f"StartOTelEnrichment's ExcludeFilters did not stick, got {started['ExcludeFilters']!r}"
    )

    updated = _retrying(
        lambda: cw.update_otel_enrichment(IncludeFilters=[{"Namespace": _NAMESPACE_B}])
    )
    assert updated["IncludeFilters"] == [{"Namespace": _NAMESPACE_B}], (
        f"UpdateOTelEnrichment's response IncludeFilters was {updated['IncludeFilters']!r}, "
        f"expected only {_NAMESPACE_B!r}"
    )
    assert updated.get("ExcludeFilters", []) == [], (
        "UpdateOTelEnrichment with only IncludeFilters must clear the previously stored "
        f"ExcludeFilters, but the response still carries {updated.get('ExcludeFilters')!r}"
    )

    got = _retrying(lambda: cw.get_otel_enrichment())
    assert got["IncludeFilters"] == [{"Namespace": _NAMESPACE_B}], (
        f"GetOTelEnrichment IncludeFilters after update was {got['IncludeFilters']!r}, "
        f"expected only {_NAMESPACE_B!r}"
    )
    assert got.get("ExcludeFilters", []) == [], (
        "GetOTelEnrichment must reflect UpdateOTelEnrichment's wholesale-replace clearing of "
        f"ExcludeFilters, but it still carries {got.get('ExcludeFilters')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
