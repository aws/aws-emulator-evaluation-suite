"""dashboard-invalid-body-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "dashboard-invalid-body-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutDashboard with a DashboardBody that is not valid JSON fails with InvalidParameterInput
    "The field DashboardBody must be a valid JSON object" and creates no dashboard; a well-formed
    body under another name creates one."""
    cw = ctx.client("cloudwatch")
    bad_name = ctx.unique_name("sim2real-dash-bad-")
    good_name = ctx.unique_name("sim2real-dash-good-")
    ctx.on_cleanup(lambda: _safe_delete(cw, good_name))

    code, message = _refusal(lambda: cw.put_dashboard(DashboardName=bad_name, DashboardBody="{not valid json!!"))
    assert code == "InvalidParameterInput", (
        f"expected InvalidParameterInput for malformed dashboard body, got {code} ({message!r})"
    )
    assert message == "The field DashboardBody must be a valid JSON object", f"unexpected InvalidParameterInput message {message!r}"

    names = {e["DashboardName"] for e in cw.list_dashboards()["DashboardEntries"]}
    assert bad_name not in names, "dashboard should not have been created from an invalid body"

    # Positive control: an identical call with a well-formed body for a different name
    # succeeds, so the rejection above is specifically about the malformed body.
    cw.put_dashboard(DashboardName=good_name, DashboardBody=json.dumps({"widgets": []}))
    names_after = {e["DashboardName"] for e in cw.list_dashboards()["DashboardEntries"]}
    assert good_name in names_after, "a well-formed PutDashboard body should have created the dashboard"


def _refusal(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_delete(cw, name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        cw.delete_dashboards(DashboardNames=[name])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
