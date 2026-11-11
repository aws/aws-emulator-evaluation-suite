"""put-dashboard-name-exceeds-length-limit-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-dashboard-name-exceeds-length-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutDashboard rejects a DashboardName longer than the documented 255-character
    maximum rather than silently truncating and accepting it; the dashboard is never
    created, and the same call with a valid-length name still succeeds."""
    cw = ctx.client("cloudwatch")
    too_long_name = "A" * 256
    body = json.dumps({"widgets": [{"type": "text", "x": 0, "y": 0, "width": 3, "height": 3,
                                     "properties": {"markdown": "sim2real check"}}]})

    error = _client_error(lambda: cw.put_dashboard(DashboardName=too_long_name, DashboardBody=body))
    assert error.get("Code") == "InvalidParameterValue", f"expected InvalidParameterValue, got {error!r}"
    assert error.get("Message") == "The value for field DashboardName is too long. It must have length less than or equal to 255.\n", (
        f"unexpected message for an over-long DashboardName: {error.get('Message')!r}"
    )

    # Effect absent: no dashboard exists under the over-long name. GetDashboard itself
    # would re-validate the (invalid) name and raise before ever checking existence, so
    # use ListDashboards -- which takes no name parameter to validate -- instead.
    all_names = {entry["DashboardName"] for entry in _list_all_dashboards(cw)}
    assert too_long_name not in all_names, "rejected dashboard name appeared in ListDashboards"

    # Positive control: same call shape, valid-length name, succeeds.
    valid_name = ctx.unique_name("sim2realdash")
    cw.put_dashboard(DashboardName=valid_name, DashboardBody=body)
    ctx.on_cleanup(lambda: cw.delete_dashboards(DashboardNames=[valid_name]))
    account = ctx.client("sts").get_caller_identity()["Account"]
    cw.tag_resource(
        ResourceARN=f"arn:aws:cloudwatch::{account}:dashboard/{valid_name}",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )

    fetched = cw.get_dashboard(DashboardName=valid_name)
    assert fetched["DashboardName"] == valid_name, (
        f"expected DashboardName={valid_name!r}, got {fetched['DashboardName']!r}"
    )
    fetched_body = json.loads(fetched["DashboardBody"])
    expected_body = json.loads(body)
    assert fetched_body == expected_body, f"expected body {expected_body!r}, got {fetched_body!r}"


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _list_all_dashboards(cw):
    entries = []
    kwargs = {}
    while True:
        page = cw.list_dashboards(**kwargs)
        entries.extend(page.get("DashboardEntries", []))
        token = page.get("NextToken")
        if not token:
            return entries
        kwargs = {"NextToken": token}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
