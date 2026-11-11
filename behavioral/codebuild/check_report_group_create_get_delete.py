"""report-group-create-get-delete."""
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

CHECK = "report-group-create-get-delete"
GROUP = 'lifecycle'
SERVICES = ['codebuild']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A created report group is ACTIVE and readable via BatchGetReportGroups; after delete it is
    listed in `reportGroupsNotFound` (no exception), and UpdateReportGroup raises ResourceNotFound."""
    cb = ctx.client("codebuild")
    rg = _create_report_group(cb, ctx, tags=[{"key": "sim2real", "value": CHECK}])
    arn = rg["arn"]
    assert rg["type"] == "TEST", rg
    assert rg["status"] == "ACTIVE", rg

    got = cb.batch_get_report_groups(reportGroupArns=[arn])
    found = {g["arn"]: g for g in got.get("reportGroups", [])}
    assert arn in found, got
    assert found[arn]["name"] == rg["name"], found[arn]

    cb.delete_report_group(arn=arn, deleteReports=True)

    after = cb.batch_get_report_groups(reportGroupArns=[arn])
    live = {g["arn"] for g in after.get("reportGroups", [])}
    assert arn not in live, after
    assert arn in after.get("reportGroupsNotFound", []), after

    try:
        cb.update_report_group(arn=arn, exportConfig={"exportConfigType": "NO_EXPORT"})
        raise AssertionError(f"UpdateReportGroup on deleted {arn} unexpectedly succeeded")
    except cb.exceptions.ResourceNotFoundException as exc:
        message = exc.response["Error"].get("Message")
        assert message == "Report group does not exist", (
            f"UpdateReportGroup on deleted {arn} must say 'Report group does not exist', got {message!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
