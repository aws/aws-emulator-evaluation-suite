"""delete-dashboard-nonexistent-returns-invalid-param."""
from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-dashboard-nonexistent-returns-invalid-param"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteDashboards for a name that doesn't correspond to an existing dashboard is a
    silent no-op on real CloudWatch -- it does not raise InvalidParameterValueException
    or any other error, and it does not touch any other, unrelated dashboard."""
    cw = ctx.client("cloudwatch")
    bogus_name = ctx.unique_name("sim2real-behav-nodash-")
    untouched_name = ctx.unique_name("sim2real-behav-untouched-")
    body = json.dumps({"widgets": []})

    cw.put_dashboard(DashboardName=untouched_name, DashboardBody=body)
    ctx.on_cleanup(lambda: _safe_delete_dashboards(ctx, [untouched_name]))

    assert untouched_name in _list_dashboard_names(cw), (
        "setup dashboard was not visible before the test"
    )

    # Must not raise -- deleting a name with nothing behind it is a successful no-op.
    cw.delete_dashboards(DashboardNames=[bogus_name])

    names_after = _list_dashboard_names(cw)
    assert bogus_name not in names_after, (
        "a dashboard name magically appeared after deleting a nonexistent dashboard"
    )
    assert untouched_name in names_after, (
        "deleting an unrelated nonexistent dashboard name must not remove a real, unrelated dashboard"
    )


def _safe_delete_dashboards(ctx: Any, names: list[str]) -> None:
    cw = ctx.client("cloudwatch")
    try:
        cw.delete_dashboards(DashboardNames=names)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _list_dashboard_names(cw) -> set[str]:
    names: set[str] = set()
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = cw.list_dashboards(**kwargs)
        names.update(entry["DashboardName"] for entry in resp.get("DashboardEntries", []))
        token = resp.get("NextToken")
        if not token:
            break
    return names


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
