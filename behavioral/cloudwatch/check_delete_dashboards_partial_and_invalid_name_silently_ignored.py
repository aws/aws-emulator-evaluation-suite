"""delete-dashboards-partial-and-invalid-name-silently-ignored."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-dashboards-partial-and-invalid-name-silently-ignored"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteDashboards naming an existing and a nonexistent dashboard succeeds and deletes the
    existing one: GetDashboard on it then fails with ResourceNotFound "Dashboard <name> does not
    exist"."""
    cw = ctx.client("cloudwatch")
    dash1 = ctx.unique_name("sim2real-behav-dash-")
    bogus_name = ctx.unique_name("sim2real-behav-dash-missing-")
    body = json.dumps({"widgets": []})

    cw.put_dashboard(DashboardName=dash1, DashboardBody=body)
    ctx.on_cleanup(lambda: _safe_delete_dashboards(ctx, [dash1]))

    # Sanity: the dashboard is really there before we touch it.
    got = cw.get_dashboard(DashboardName=dash1)
    assert got["DashboardName"] == dash1, f"expected GetDashboard to return {dash1!r}, got {got['DashboardName']!r}"
    assert json.loads(got["DashboardBody"]) == {"widgets": []}, (
        f"expected the freshly-put body {{'widgets': []}}, got {got['DashboardBody']!r}"
    )

    # Batch-deleting a real name plus a nonexistent one is *not* rejected: the
    # nonexistent name is silently ignored and the call succeeds.
    # A rejection of the mixed-name batch delete raises here.
    cw.delete_dashboards(DashboardNames=[dash1, bogus_name])
    # The delete takes effect asynchronously, so GetDashboard gets a bounded window to observe
    # it. GetDashboard's not-found code is "ResourceNotFound" (not the "DashboardNotFoundError"
    # shape name some other dashboard errors use).
    code2, message2 = _poll_until_dashboard_gone(ctx, dash1)
    assert code2 == "ResourceNotFound", (
        f"dash1 should have been deleted as part of the partial-success batch, got {code2!r}"
    )
    expected_message = f"Dashboard {dash1} does not exist"
    assert message2 == expected_message, f"expected message {expected_message!r}, got {message2!r}"


def _safe_delete_dashboards(ctx: Any, names: list[str]) -> None:
    from botocore.exceptions import ClientError

    cw = ctx.client("cloudwatch")
    try:
        cw.delete_dashboards(DashboardNames=names)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _poll_until_dashboard_gone(ctx: Any, name: str, timeout_s: float = 30.0, interval_s: float = 2.0) -> tuple[str | None, str | None]:
    """Poll GetDashboard until it reports ResourceNotFound; return the last (Code, Message)."""
    from botocore.exceptions import ClientError

    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + timeout_s
    last = (None, None)
    while time.monotonic() < deadline:
        try:
            cw.get_dashboard(DashboardName=name)
            last = (None, None)
        except ClientError as err:
            last = (err.response["Error"]["Code"], err.response["Error"].get("Message"))
            if last[0] == "ResourceNotFound":
                return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
