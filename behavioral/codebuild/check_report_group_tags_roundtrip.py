"""report-group-tags-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

def _create_report_group(cb, ctx, tags=None):
    """Create a uniquely-named TEST report group; register teardown; return its reportGroup dict."""
    kwargs = {"name": ctx.unique_name("sim2real-behav-rg-"), "type": "TEST",
              "exportConfig": {"exportConfigType": "NO_EXPORT"}}
    if tags is not None:
        kwargs["tags"] = tags
    rg = cb.create_report_group(**kwargs)["reportGroup"]
    ctx.on_cleanup(lambda: cb.delete_report_group(arn=rg["arn"], deleteReports=True))
    return rg

CHECK = "report-group-tags-roundtrip"
GROUP = 'tags'
SERVICES = ['codebuild']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags supplied at CreateReportGroup time are persisted and echoed by
    BatchGetReportGroups (CodeBuild uses the lowercase key/value tag shape);
    deleting the report group removes it from that same independent read."""
    cb = ctx.client("codebuild")
    key = ctx.unique_name("sim2real-behav-tagkey-")
    rg = _create_report_group(cb, ctx, tags=[{"key": key, "value": "engineering"}])
    arn = rg["arn"]

    got = cb.batch_get_report_groups(reportGroupArns=[arn])
    found = {g["arn"]: g for g in got.get("reportGroups", [])}
    assert arn in found, got
    tags_found = {t["key"]: t["value"] for t in found[arn].get("tags", [])}
    assert tags_found.get(key) == "engineering", found[arn]

    cb.delete_report_group(arn=arn, deleteReports=True)
    after = cb.batch_get_report_groups(reportGroupArns=[arn])
    live = {g["arn"] for g in after.get("reportGroups", [])}
    assert arn not in live, after


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
