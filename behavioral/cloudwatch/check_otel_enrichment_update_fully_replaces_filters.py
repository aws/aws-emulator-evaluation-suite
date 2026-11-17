"""otel-enrichment-update-fully-replaces-filters."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "otel-enrichment-update-fully-replaces-filters"
GROUP = "otel-enrichment"
SERVICES = ["cloudwatch"]


def _restore(cw, status: str, include: list, exclude: list):
    if status != "Running":
        cw.stop_otel_enrichment()
    else:
        cw.update_otel_enrichment(IncludeFilters=include, ExcludeFilters=exclude)


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:representation",
    "plane:control",
    "resource:account-singleton:cloudwatch-otel-enrichment",
)
def run(ctx) -> None:
    """UpdateOTelEnrichment fully replaces IncludeFilters/ExcludeFilters -- a value omitted from
    the update is cleared, not merged with what was there -- visible only via a later GetOTelEnrichment."""
    cw = ctx.client("cloudwatch")

    original = cw.get_otel_enrichment()
    original_status = original["Status"]
    original_include = original.get("IncludeFilters", [])
    original_exclude = original.get("ExcludeFilters", [])
    ctx.on_cleanup(lambda: _restore(cw, original_status, original_include, original_exclude))

    ns_one = ctx.unique_name("Sim2RealOTelNsOne")
    ns_two = ctx.unique_name("Sim2RealOTelNsTwo")
    ns_three = ctx.unique_name("Sim2RealOTelNsThree")

    if original_status != "Running":
        cw.start_otel_enrichment(IncludeFilters=[{"Namespace": ns_one}])
    else:
        cw.update_otel_enrichment(IncludeFilters=[{"Namespace": ns_one}], ExcludeFilters=[])

    baseline = cw.get_otel_enrichment()
    assert baseline["Status"] == "Running", f"expected Running, got {baseline['Status']!r}"
    assert baseline["IncludeFilters"] == [{"Namespace": ns_one}], (
        f"expected IncludeFilters [{{'Namespace': {ns_one!r}}}], got {baseline.get('IncludeFilters')!r}"
    )
    assert baseline.get("ExcludeFilters", []) == [], (
        f"expected no ExcludeFilters at baseline, got {baseline.get('ExcludeFilters')!r}"
    )

    cw.update_otel_enrichment(
        IncludeFilters=[{"Namespace": ns_two, "MetricNames": ["Foo"]}],
        ExcludeFilters=[{"Namespace": ns_one}],
    )
    after_update = cw.get_otel_enrichment()
    assert after_update["Status"] == "Running", (
        f"UpdateOTelEnrichment must not change Status, got {after_update['Status']!r}"
    )
    assert after_update["IncludeFilters"] == [{"Namespace": ns_two, "MetricNames": ["Foo"]}], (
        f"expected the update's IncludeFilters to replace the baseline, got {after_update.get('IncludeFilters')!r}"
    )
    assert after_update["ExcludeFilters"] == [{"Namespace": ns_one}], (
        f"expected ExcludeFilters [{{'Namespace': {ns_one!r}}}], got {after_update.get('ExcludeFilters')!r}"
    )

    # A second update that omits ExcludeFilters clears it -- full replacement, not a merge.
    cw.update_otel_enrichment(IncludeFilters=[{"Namespace": ns_three}])
    after_clear = cw.get_otel_enrichment()
    assert after_clear["IncludeFilters"] == [{"Namespace": ns_three}], (
        f"expected IncludeFilters [{{'Namespace': {ns_three!r}}}], got {after_clear.get('IncludeFilters')!r}"
    )
    assert after_clear.get("ExcludeFilters", []) == [], (
        f"expected ExcludeFilters cleared by the omitting update, got {after_clear.get('ExcludeFilters')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
