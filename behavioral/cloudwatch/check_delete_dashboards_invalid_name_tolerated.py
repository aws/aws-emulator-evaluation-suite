"""delete-dashboards-invalid-name-tolerated."""
from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-dashboards-invalid-name-tolerated"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """DeleteDashboards does not error on an unknown dashboard name, and still deletes the valid ones in the same batch."""
    cw = ctx.client("cloudwatch")
    good_name = ctx.unique_name("sim2real-behav-dash-")
    bogus_name = ctx.unique_name("sim2real-behav-dash-missing-")
    body = json.dumps({"widgets": []})

    cw.put_dashboard(DashboardName=good_name, DashboardBody=body)
    state = {"pending_cleanup": True}

    def _cleanup() -> None:
        if state["pending_cleanup"]:
            try:
                cw.delete_dashboards(DashboardNames=[good_name])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFound":
                    raise

    ctx.on_cleanup(_cleanup)

    assert good_name in _list_dashboard_names(cw), "setup dashboard was not visible before the test"

    # Real CloudWatch does not raise for a nonexistent name mixed into the batch -- it is
    # simply a no-op for that name -- so the call itself must succeed.
    try:
        cw.delete_dashboards(DashboardNames=[good_name, bogus_name])
    except ClientError as exc:
        raise AssertionError(
            f"expected DeleteDashboards([{good_name}, {bogus_name}]) to succeed despite the "
            f"unknown name in the batch, got error {exc.response['Error']['Code']!r}"
        ) from exc

    names_after = _list_dashboard_names(cw)
    state["pending_cleanup"] = good_name in names_after
    assert good_name not in names_after, (
        "the valid dashboard in the batch was not deleted despite AWS's documented "
        "partial-failure ('delete as many as possible') behavior for DeleteDashboards"
    )

    final_code, final_message = _error(lambda: cw.get_dashboard(DashboardName=good_name))
    assert final_code == "ResourceNotFound", (
        f"expected GetDashboard({good_name}) to report ResourceNotFound after the batch "
        f"delete that named it, got {final_code!r}"
    )
    expected_message = f"Dashboard {good_name} does not exist"
    assert final_message == expected_message, f"expected message {expected_message!r}, got {final_message!r}"


def _error(fn):
    """Call fn(); return the botocore (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _list_dashboard_names(cw: Any) -> set[str]:
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
