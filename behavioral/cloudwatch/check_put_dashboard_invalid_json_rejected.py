"""put-dashboard-invalid-json-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-dashboard-invalid-json-rejected"
GROUP = 'overly-permissive'
SERVICES = ['cloudwatch']

def _err(fn):
    """Call fn(); return the botocore Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutDashboard rejects a DashboardBody that is not valid JSON (overly-permissive check)."""
    cw = ctx.client("cloudwatch")
    dashboard_name = ctx.unique_name("sim2real-behav-cwprobe-dash-")

    def op():
        return cw.put_dashboard(DashboardName=dashboard_name, DashboardBody="{not json at all")

    error = _err(op)
    assert error.get("Code") == "InvalidParameterInput", (
        f"expected a dashboard input-validation error for malformed JSON, got {error!r}"
    )
    assert error.get("Message") == "The field DashboardBody must be a valid JSON object", (
        f"unexpected message for malformed JSON: {error.get('Message')!r}"
    )

    # Must not have been created despite the error.
    def get_op():
        return cw.get_dashboard(DashboardName=dashboard_name)

    get_error = _err(get_op)
    assert get_error.get("Code") == "ResourceNotFound", (
        f"malformed PutDashboard must not create the dashboard, got GetDashboard error {get_error!r}"
    )
    assert get_error.get("Message") == f"Dashboard {dashboard_name} does not exist", (
        f"unexpected not-found message: {get_error.get('Message')!r}"
    )

    # Positive control: the identical call for the same name with a well-formed body
    # succeeds. Without this, the two assertions above cannot tell "rejects malformed
    # JSON" from "rejects every PutDashboard call" -- a target with no PutDashboard
    # implementation at all would otherwise score green.
    good_body = json.dumps({"widgets": []})
    put_resp = cw.put_dashboard(DashboardName=dashboard_name, DashboardBody=good_body)
    ctx.on_cleanup(lambda: cw.delete_dashboards(DashboardNames=[dashboard_name]))
    assert put_resp.get("DashboardValidationMessages", []) == [], (
        f"expected a well-formed empty-widgets body to be accepted with no validation "
        f"messages, got {put_resp}"
    )
    got = cw.get_dashboard(DashboardName=dashboard_name)
    assert json.loads(got["DashboardBody"]) == json.loads(good_body), (
        f"expected the stored body to round-trip, got {got.get('DashboardBody')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
