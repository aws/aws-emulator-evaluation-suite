"""get-dashboard-nonexistent-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-dashboard-nonexistent-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDashboard on a name that was never created must fail with ResourceNotFound,
    not return an empty/default success payload."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-behav-missing-dash-")

    # Despite the "DashboardNotFoundError" shape name implied by the API docs, real
    # CloudWatch's dashboard actions use the short-form generic code on the wire.
    code, message = _error(lambda: cw.get_dashboard(DashboardName=name))
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code}"
    assert message == f"Dashboard {name} does not exist", f"unexpected GetDashboard message {message!r}"


def _error(fn):
    """Call fn(); return the ClientError (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected ResourceNotFound, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
