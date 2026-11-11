"""list-work-groups-reflects-live-creation-deletion."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-work-groups-reflects-live-creation-deletion"
GROUP = "state-machine"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListWorkGroups includes a workgroup right after CreateWorkGroup (ENABLED) and excludes it
    right after DeleteWorkGroup; GetWorkGroup on the deleted name fails not-found and the freed
    name is immediately reusable."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-behav-wg-")

    before_names = {w["Name"] for w in _workgroups(athena)}
    assert name not in before_names, f"unique name {name!r} already present before creation"

    athena.create_work_group(Name=name)
    ctx.on_cleanup(lambda: _safe_delete_workgroup(athena, name))

    after_create = _workgroups(athena)
    match = next((w for w in after_create if w["Name"] == name), None)
    assert match is not None, "workgroup missing from ListWorkGroups immediately after creation"
    assert match["State"] == "ENABLED", f"expected ENABLED, got {match['State']!r}"

    athena.delete_work_group(WorkGroup=name)
    after_delete_names = {w["Name"] for w in _workgroups(athena)}
    assert name not in after_delete_names, "deleted workgroup still present in ListWorkGroups"

    get_error = _client_error(lambda: athena.get_work_group(WorkGroup=name))
    assert get_error.get("Code") == "InvalidRequestException", (
        f"expected InvalidRequestException from GetWorkGroup on the deleted name, got {get_error!r}"
    )
    assert get_error.get("Message") == "WorkGroup is not found.", (
        f"GetWorkGroup on the deleted name: unexpected message {get_error.get('Message')!r}"
    )

    # The freed name is immediately reusable, and the recreated workgroup is once
    # again a live, independently-readable ENABLED entry (not a tombstone).
    athena.create_work_group(Name=name)
    recreated = athena.get_work_group(WorkGroup=name)["WorkGroup"]
    assert recreated["State"] == "ENABLED", (
        f"expected ENABLED after recreating deleted name, got {recreated['State']!r}"
    )
    recreated_names = {w["Name"] for w in _workgroups(athena)}
    assert name in recreated_names, "recreated workgroup missing from ListWorkGroups"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. A success raises: AWS rejects this call, and
    accepting it is a distinct failure from returning the wrong error code."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _workgroups(athena):
    out = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = athena.list_work_groups(**kwargs)
        out.extend(resp["WorkGroups"])
        token = resp.get("NextToken")
        if not token:
            break
    return out


def _safe_delete_workgroup(athena, workgroup):
    try:
        athena.delete_work_group(WorkGroup=workgroup)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err.get("Code") == "InvalidRequestException" and "not found" in err.get("Message", "")):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
