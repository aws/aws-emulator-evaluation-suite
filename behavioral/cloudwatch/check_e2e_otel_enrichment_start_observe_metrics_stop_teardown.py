"""e2e-otel-enrichment-start-observe-metrics-stop-teardown."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-otel-enrichment-start-observe-metrics-stop-teardown"
GROUP = "e2e"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "resource:account-singleton:cloudwatch-otel-enrichment")
def run(ctx) -> None:
    """Stop/StartOTelEnrichment move GetOTelEnrichment between Stopped and Running, and a custom
    metric published while running stays listed by ListMetrics after enrichment stops.
    """
    cw = ctx.client("cloudwatch")

    original_status = cw.get_otel_enrichment()["Status"]

    def _restore():
        if original_status == "Running":
            _safe_call(cw.start_otel_enrichment)
        else:
            _safe_call(cw.stop_otel_enrichment)

    ctx.on_cleanup(_restore)

    try:
        cw.stop_otel_enrichment()
    except ClientError as exc:
        raise AssertionError(
            "StopOTelEnrichment was rejected; account may need 'resource tags on "
            f"telemetry' enabled via ObservabilityAdmin first (see EnableResourceTagsOnTelemetry): {exc}"
        ) from exc
    stopped = _poll_until(
        lambda: cw.get_otel_enrichment()["Status"], lambda s: s == "Stopped", timeout_s=30, interval_s=2
    )
    assert stopped == "Stopped", f"expected GetOTelEnrichment Status='Stopped' after StopOTelEnrichment, got {stopped!r}"

    cw.start_otel_enrichment()
    running = _poll_until(
        lambda: cw.get_otel_enrichment()["Status"], lambda s: s == "Running", timeout_s=30, interval_s=2
    )
    assert running == "Running", f"expected GetOTelEnrichment Status='Running' after StartOTelEnrichment, got {running!r}"

    namespace = ctx.unique_name("Sim2Real/OTelEnrichment-")
    metric_name = "EnrichmentProbe"
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": metric_name, "Value": 1.0, "Unit": "Count"}],
    )

    listed = _poll_until(
        lambda: cw.list_metrics(Namespace=namespace, MetricName=metric_name)["Metrics"],
        lambda metrics: len(metrics) >= 1,
        timeout_s=180,
        interval_s=10,
    )
    assert listed[0]["Namespace"] == namespace, f"expected ListMetrics to report Namespace={namespace!r}, got {listed[0]['Namespace']!r}"
    assert listed[0]["MetricName"] == metric_name, f"expected ListMetrics to report MetricName={metric_name!r}, got {listed[0]['MetricName']!r}"

    cw.stop_otel_enrichment()
    stopped_again = _poll_until(
        lambda: cw.get_otel_enrichment()["Status"], lambda s: s == "Stopped", timeout_s=30, interval_s=2
    )
    assert stopped_again == "Stopped", f"expected GetOTelEnrichment Status='Stopped' after the second StopOTelEnrichment, got {stopped_again!r}"

    # Enrichment adds nothing ListMetrics shows for a custom metric; stopping it must not hide data.
    still_listed = cw.list_metrics(Namespace=namespace, MetricName=metric_name)["Metrics"]
    assert len(still_listed) >= 1, (
        f"expected {namespace}/{metric_name} to remain visible via ListMetrics after StopOTelEnrichment, "
        f"got {len(still_listed)} matching metrics"
    )


def _safe_call(fn):
    try:
        fn()
    except ClientError:
        pass


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never met, last observed value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
