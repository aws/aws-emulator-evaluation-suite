"""put-dashboard-invalid-json-body-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "put-dashboard-invalid-json-body-rejected"
GROUP = "representation"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutDashboard with a DashboardBody that is not JSON is rejected with InvalidParameterInput "The field
    DashboardBody must be a valid JSON object" and creates nothing (GetDashboard: ResourceNotFound), while
    a well-formed body under another name is accepted and reads back unchanged."""
    cw = ctx.client("cloudwatch")
    bad_name = ctx.unique_name("sim2real-behav-cw-dash-badjson-")
    good_name = ctx.unique_name("sim2real-behav-cw-dash-goodjson-")
    invalid_body = '{"widgets": [ this is not valid json,,, }'

    error = _client_error(lambda: cw.put_dashboard(DashboardName=bad_name, DashboardBody=invalid_body))
    assert error.get("Code") == "InvalidParameterInput", f"unexpected error: {error!r}"
    assert error.get("Message") == "The field DashboardBody must be a valid JSON object", (
        f"unexpected message for a non-JSON DashboardBody: {error.get('Message')!r}"
    )

    # Effect absent: the malformed dashboard must not exist.
    not_found = _client_error(lambda: cw.get_dashboard(DashboardName=bad_name))
    assert not_found.get("Code") == "ResourceNotFound", f"unexpected error: {not_found!r}"
    assert not_found.get("Message") == f"Dashboard {bad_name} does not exist", (
        f"unexpected not-found message: {not_found.get('Message')!r}"
    )
    names = [d["DashboardName"] for d in cw.list_dashboards()["DashboardEntries"]]
    assert bad_name not in names, f"malformed PutDashboard must not create {bad_name!r}, but it appears in ListDashboards: {names}"

    # Positive control: a syntactically valid body for a different name succeeds.
    good_body = json.dumps(
        {"widgets": [{"type": "text", "x": 0, "y": 0, "width": 3, "height": 3, "properties": {"markdown": "ok"}}]}
    )
    put_resp = cw.put_dashboard(DashboardName=good_name, DashboardBody=good_body)
    ctx.on_cleanup(lambda: cw.delete_dashboards(DashboardNames=[good_name]))
    assert put_resp.get("DashboardValidationMessages", []) == [], (
        f"well-formed body for {good_name!r} produced validation messages: {put_resp.get('DashboardValidationMessages')}"
    )
    got = cw.get_dashboard(DashboardName=good_name)
    got_body = json.loads(got["DashboardBody"])
    assert got_body == json.loads(good_body), f"GetDashboard body {got_body!r} did not round-trip the body put for {good_name!r}"


def _client_error(fn):
    """Call fn(); return the botocore Error dict if a ClientError is raised. A SUCCESS raises
    AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
