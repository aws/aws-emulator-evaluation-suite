"""put-dashboard-name-invalid-characters-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-dashboard-name-invalid-characters-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutDashboard with a disallowed DashboardName and a malformed body reports the name error first
    (InvalidParameterValue with its exact message) and creates nothing, while a valid name with a
    well-formed body is accepted with no validation messages and readable through GetDashboard."""
    cw = ctx.client("cloudwatch")
    bad_name = ctx.unique_name("sim2real-cw-dash-") + " !"
    malformed_body = "{this is not valid dashboard json"

    error = _client_error(
        lambda: cw.put_dashboard(DashboardName=bad_name, DashboardBody=malformed_body)
    )
    assert error.get("Code") == "InvalidParameterValue", f"got {error!r}"
    assert error.get("Message") == "The value for field DashboardName contains invalid characters. It can only contain alphanumerics, dash (-) and underscore (_).\n", (
        f"unexpected message for a disallowed DashboardName: {error.get('Message')!r}"
    )

    # effect absent: no dashboard was ever created under that (invalid) name
    names = _list_all_dashboard_names(ctx)
    assert bad_name not in names, f"{bad_name!r} unexpectedly present in {names!r}"

    # positive control: a valid name and well-formed body succeeds
    good_name = ctx.unique_name("sim2real-cw-dash-")
    good_body = json.dumps({"widgets": []})
    resp = cw.put_dashboard(DashboardName=good_name, DashboardBody=good_body)
    ctx.on_cleanup(lambda: _safe_delete_dashboard(ctx, good_name))
    assert resp["DashboardValidationMessages"] == [], (
        f"expected no validation messages, got {resp['DashboardValidationMessages']!r}"
    )
    fetched = cw.get_dashboard(DashboardName=good_name)
    assert fetched["DashboardName"] == good_name, (
        f"expected {good_name!r}, got {fetched['DashboardName']!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _list_all_dashboard_names(ctx) -> list[str]:
    cw = ctx.client("cloudwatch")
    names: list[str] = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = cw.list_dashboards(**kwargs)
        names.extend(entry["DashboardName"] for entry in resp.get("DashboardEntries", []))
        token = resp.get("NextToken")
        if not token:
            break
    return names


def _safe_delete_dashboard(ctx, name: str) -> None:
    try:
        ctx.client("cloudwatch").delete_dashboards(DashboardNames=[name])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
