"""put-dashboard-invalid-body-rejected."""
from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-dashboard-invalid-body-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """PutDashboard rejects a malformed DashboardBody with InvalidParameterInput and does not store it."""
    cw = ctx.client("cloudwatch")
    dashboard_name = ctx.unique_name("sim2real-behav-dash-invalid-")
    ctx.on_cleanup(lambda: _safe_delete(cw, dashboard_name))

    # Not valid JSON at all.
    error = _client_error(lambda: cw.put_dashboard(DashboardName=dashboard_name, DashboardBody="{not-valid-json"))
    assert error.get("Code") == "InvalidParameterInput", (
        f"expected InvalidParameterInput for a non-JSON DashboardBody, got {error!r}"
    )
    assert error.get("Message") == "The field DashboardBody must be a valid JSON object", (
        f"unexpected message for a non-JSON DashboardBody: {error.get('Message')!r}"
    )
    assert not _dashboard_exists(cw, dashboard_name), (
        "PutDashboard with an invalid body must not create a partially-stored dashboard"
    )

    # Syntactically valid JSON, but an invalid widget definition (unknown widget "type").
    # Unlike malformed JSON, PutDashboard does not reject this outright: it accepts the
    # call and reports the problem via DashboardValidationMessages rather than raising a
    # ClientError, and it still stores the (invalid) widget definition.
    bad_widget_body = json.dumps(
        {"widgets": [{"type": "not-a-real-widget-type", "x": 0, "y": 0, "width": 1, "height": 1, "properties": {}}]}
    )
    put_resp = cw.put_dashboard(DashboardName=dashboard_name, DashboardBody=bad_widget_body)
    assert put_resp.get("DashboardValidationMessages"), (
        "expected PutDashboard to report a validation warning for an unrecognized widget "
        f"type, got none: {put_resp}"
    )
    stored = cw.get_dashboard(DashboardName=dashboard_name)
    stored_body = json.loads(stored["DashboardBody"])
    assert stored_body == json.loads(bad_widget_body), (
        "PutDashboard accepts an unrecognized widget type (surfacing a validation warning "
        "instead of an error) and must store it verbatim rather than silently dropping or "
        f"correcting it, got stored body {stored_body!r}"
    )

    # Sanity: a well-formed body for the same name is accepted, proving the prior rejections
    # were about body validity and not, say, a name collision or throttling.
    cw.put_dashboard(DashboardName=dashboard_name, DashboardBody=json.dumps({"widgets": []}))
    assert _dashboard_exists(cw, dashboard_name), (
        "a well-formed body for the same dashboard name must succeed and be readable back, "
        "proving the prior rejections were about body validity and not a name collision or "
        "throttling"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _dashboard_exists(cw: Any, name: str) -> bool:
    try:
        cw.get_dashboard(DashboardName=name)
        return True
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFound":
            return False
        raise



def _safe_delete(cw: Any, name: str) -> None:
    try:
        cw.delete_dashboards(DashboardNames=[name])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
