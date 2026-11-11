"""op-contract-deleteDashboards."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteDashboards"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteDashboards tolerates unknown names in the batch: a call naming one real
    dashboard plus one bogus name succeeds without error, deletes the real dashboard
    that was named, and leaves an untouched sibling (not named in the call) alone."""
    cw = ctx.client("cloudwatch")
    name_a = ctx.unique_name("sim2real-cw-dash-a-")
    name_b = ctx.unique_name("sim2real-cw-dash-b-")
    body = json.dumps({"widgets": []})

    cw.put_dashboard(DashboardName=name_a, DashboardBody=body, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_dashboards_ignore_missing(cw, [name_a]))
    cw.put_dashboard(DashboardName=name_b, DashboardBody=body, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_dashboards_ignore_missing(cw, [name_b]))

    fetched = cw.get_dashboard(DashboardName=name_a)
    assert json.loads(fetched["DashboardBody"]) == {"widgets": []}, (
        f"expected {name_a}'s body to round-trip as an empty widget list, got {fetched['DashboardBody']!r}"
    )
    assert fetched["DashboardName"] == name_a, (
        f"expected GetDashboard to echo the name it was asked for, got {fetched['DashboardName']!r}"
    )

    bogus_name = ctx.unique_name("sim2real-cw-dash-missing-")
    try:
        cw.delete_dashboards(DashboardNames=[name_a, bogus_name])
    except ClientError as err:
        raise AssertionError(
            f"expected DeleteDashboards([{name_a}, {bogus_name}]) to succeed despite the "
            f"bogus name, got error {err.response['Error']['Code']}"
        ) from err

    # The named real dashboard was actually deleted by the call, even though the batch
    # also named a dashboard that never existed. GetDashboard has been observed to briefly
    # still serve the pre-delete state immediately after DeleteDashboards returns, so this
    # is a bounded retry rather than a single immediate read.
    final_code_a, final_msg_a = _wait_for_refusal(lambda: cw.get_dashboard(DashboardName=name_a))
    assert final_code_a == "ResourceNotFound", (
        f"expected {name_a} to be deleted by the DeleteDashboards call that named it, "
        f"got code {final_code_a!r}"
    )
    expected_msg_a = f"Dashboard {name_a} does not exist"
    assert final_msg_a == expected_msg_a, (
        f"expected the GetDashboard refusal message {expected_msg_a!r}, got {final_msg_a!r}"
    )

    # name_b was never named in that call, so it must be untouched.
    still_there = cw.get_dashboard(DashboardName=name_b)
    assert still_there["DashboardName"] == name_b, (
        f"expected {name_b} to be untouched by a DeleteDashboards call that never named it, "
        f"got {still_there['DashboardName']!r}"
    )

    cw.delete_dashboards(DashboardNames=[name_b])
    final_code_b, final_msg_b = _wait_for_refusal(lambda: cw.get_dashboard(DashboardName=name_b))
    assert final_code_b == "ResourceNotFound", (
        f"expected {name_b} to be deleted by its own DeleteDashboards call, "
        f"got code {final_code_b!r}"
    )
    expected_msg_b = f"Dashboard {name_b} does not exist"
    assert final_msg_b == expected_msg_b, (
        f"expected the GetDashboard refusal message {expected_msg_b!r}, got {final_msg_b!r}"
    )


def _delete_dashboards_ignore_missing(cw, names: list[str]) -> None:
    try:
        cw.delete_dashboards(DashboardNames=names)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _wait_for_refusal(fn, timeout_s: float = 30.0, interval_s: float = 2.0) -> tuple[str, str]:
    """Call fn until it raises a ClientError; return its (code, message).

    Raises AssertionError when fn still succeeds at the deadline."""
    import time

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"expected the call to be refused within {timeout_s}s, but it kept succeeding")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
