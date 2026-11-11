"""get-dashboard-invalid-parameter-value-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-dashboard-invalid-parameter-value-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDashboard with a malformed dashboard name (invalid characters / too long) is
    rejected as invalid input, not treated as a plain not-found lookup."""
    cw = ctx.client("cloudwatch")

    # Positive control: prove GetDashboard works for this account/credentials before
    # relying on it raising for a bad name -- otherwise a target that rejects every
    # GetDashboard call would score identically to one that correctly discriminates
    # malformed input.
    dash_name = ctx.unique_name("sim2real-behav-cw-dash-")
    body = {"widgets": []}
    cw.put_dashboard(
        DashboardName=dash_name,
        DashboardBody=json.dumps(body),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_dashboards(DashboardNames=[dash_name]))
    got = cw.get_dashboard(DashboardName=dash_name)
    assert got["DashboardName"] == dash_name, got

    # Valid dashboard names only contain A-Z, a-z, 0-9, "-", "_" and are <= 255 chars.
    # Use a name that violates both the character set and the length bound so the
    # rejection is unambiguous. botocore's GetDashboard model carries no client-side
    # pattern/length constraint on DashboardName, so this request reaches the service --
    # a ParamValidationError here would mean the request never left the SDK and must not
    # be counted as a rejection.
    malformed_name = ("bad:dashboard/name#" * 20) + "!"

    try:
        cw.get_dashboard(DashboardName=malformed_name)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message")
        assert code == "InvalidParameterValue", code
        assert message == (
            "The value for field DashboardName contains invalid characters. It can only contain "
            "alphanumerics, dash (-) and underscore (_).\n"
            "The value for field DashboardName is too long. It must have length less than or equal to 255.\n"
        ), f"unexpected InvalidParameterValue message {message!r}"
        return
    raise AssertionError("GetDashboard() with a malformed DashboardName did not raise any error")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
