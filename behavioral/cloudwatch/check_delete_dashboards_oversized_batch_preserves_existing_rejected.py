"""delete-dashboards-oversized-batch-preserves-existing-rejected."""
from __future__ import annotations

import json
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-dashboards-oversized-batch-preserves-existing-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A real dashboard embedded in a >100-name DeleteDashboards batch survives the rejection."""
    cw = ctx.client("cloudwatch")

    real_name = ctx.unique_name("sim2real-behav-dashboard-")
    body = json.dumps({"widgets": []})
    cw.put_dashboard(DashboardName=real_name, DashboardBody=body)
    ctx.on_cleanup(lambda: _safe(lambda: cw.delete_dashboards(DashboardNames=[real_name])))

    # 100 nonexistent names + the one real dashboard = 101 total, over the documented cap.
    oversized = [f"sim2real-behav-nonexistent-dashboard-{i}" for i in range(100)] + [real_name]
    assert len(oversized) == 101, f"expected exactly 101 names in the oversized batch, got {len(oversized)}"

    code, message = _error(lambda: cw.delete_dashboards(DashboardNames=oversized))
    assert code == "InvalidParameterValue", (
        f"expected an InvalidParameterValue-style rejection for a >100-name batch, got {code!r}"
    )
    expected_message = "Field DashboardNames can contain up to 100 elements.\n"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The real dashboard, included in the rejected batch, must not have been deleted.
    got = cw.get_dashboard(DashboardName=real_name)
    assert got["DashboardName"] == real_name, (
        f"expected the rejected oversized batch to leave {real_name!r} untouched, got {got!r}"
    )

    # Positive control: without the >100 name that triggered the rejection above, the
    # identical operation on the same real dashboard actually deletes it. This is what
    # separates "rejects batches over the documented cap" from a target that rejects
    # every DeleteDashboards call outright -- the latter would otherwise pass everything
    # asserted so far.
    # A rejection of the in-bounds single-name delete raises here.
    cw.delete_dashboards(DashboardNames=[real_name])
    not_found_code, not_found_message = _error(lambda: cw.get_dashboard(DashboardName=real_name))
    assert not_found_code == "ResourceNotFound", (
        f"expected {real_name!r} to be gone after the in-bounds delete, got {not_found_code!r}"
    )
    expected_not_found = f"Dashboard {real_name} does not exist"
    assert not_found_message == expected_not_found, (
        f"expected message {expected_not_found!r}, got {not_found_message!r}"
    )


def _safe(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _error(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn(); return the botocore (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
