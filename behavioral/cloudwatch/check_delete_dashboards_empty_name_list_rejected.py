"""delete-dashboards-empty-name-list-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-dashboards-empty-name-list-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDashboards rejects an empty DashboardNames array instead of treating it as a no-op."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-cw-dash-del-")
    body = json.dumps({"widgets": []})
    cw.put_dashboard(DashboardName=name, DashboardBody=body)
    ctx.on_cleanup(lambda: _safe_delete_dashboard(ctx, name))

    code, message = _error(lambda: cw.delete_dashboards(DashboardNames=[]))
    assert code == "InvalidParameterValue", (
        f"expected DeleteDashboards(DashboardNames=[]) to be rejected with "
        f"InvalidParameterValue, got {code!r}"
    )
    expected_message = "Field DashboardNames is required and has to contain at least 1 element.\n"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the existing dashboard was left untouched by the rejected call
    fetched = cw.get_dashboard(DashboardName=name)
    assert fetched["DashboardName"] == name, (
        f"expected the dashboard {name!r} to survive the rejected empty-list delete, "
        f"got DashboardName={fetched['DashboardName']!r}"
    )

    # positive control: a non-empty DashboardNames array actually deletes the dashboard
    cw.delete_dashboards(DashboardNames=[name])
    not_found_code, not_found_message = _error(lambda: cw.get_dashboard(DashboardName=name))
    assert not_found_code == "ResourceNotFound", (
        f"expected GetDashboard({name!r}) to 404 with ResourceNotFound after the real "
        f"delete, got {not_found_code!r}"
    )
    expected_not_found = f"Dashboard {name} does not exist"
    assert not_found_message == expected_not_found, (
        f"expected message {expected_not_found!r}, got {not_found_message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_delete_dashboard(ctx, name: str) -> None:
    try:
        ctx.client("cloudwatch").delete_dashboards(DashboardNames=[name])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
