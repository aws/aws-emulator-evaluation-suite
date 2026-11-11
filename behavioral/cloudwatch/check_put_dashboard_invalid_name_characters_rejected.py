"""put-dashboard-invalid-name-characters-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-dashboard-invalid-name-characters-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutDashboard with a DashboardName holding a space and '!' is rejected with InvalidParameterValue
    and its exact message and creates nothing, while a name of only alphanumerics, '-' and '_' is
    accepted and readable through GetDashboard."""
    cw = ctx.client("cloudwatch")
    bad_name = ctx.unique_name("sim2real-dashboard-") + " bad!"
    good_name = ctx.unique_name("sim2real-dashboard-")
    body = json.dumps({"widgets": []})

    error = _client_error(lambda: cw.put_dashboard(DashboardName=bad_name, DashboardBody=body))
    # A disallowed DashboardName gets InvalidParameterValue, not the InvalidParameterInput
    # the API reference documents for a malformed DashboardBody.
    assert error.get("Code") == "InvalidParameterValue", f"expected InvalidParameterValue, got {error!r}"
    assert error.get("Message") == "The value for field DashboardName contains invalid characters. It can only contain alphanumerics, dash (-) and underscore (_).\n", (
        f"unexpected message for a disallowed DashboardName: {error.get('Message')!r}"
    )

    # effect absent: no dashboard was created under the rejected name
    names = {e["DashboardName"] for e in cw.list_dashboards()["DashboardEntries"]}
    assert bad_name not in names, f"rejected dashboard {bad_name!r} appeared in ListDashboards"

    # positive control: a name using only the documented valid characters succeeds
    cw.put_dashboard(DashboardName=good_name, DashboardBody=body)
    ctx.on_cleanup(lambda: cw.delete_dashboards(DashboardNames=[good_name]))
    got = cw.get_dashboard(DashboardName=good_name)
    assert got["DashboardName"] == good_name, (
        f"expected GetDashboard to return {good_name!r}, got {got['DashboardName']!r}"
    )


def _client_error(fn):
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, call succeeded with {resp!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
