"""op-contract-putDashboard-tags-at-creation."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-putDashboard-tags-at-creation"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutDashboard applies Tags only at creation: a later PutDashboard replaces the body but its Tags are
    ignored, and invalid JSON is rejected with InvalidParameterInput "The field DashboardBody must be a
    valid JSON object" leaving the stored body unchanged."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-cwdashtags-").replace("-", "_")
    ctx.on_cleanup(lambda: _safe_delete_dashboard(cw, name))

    body_v1 = {"widgets": [{"type": "text", "x": 0, "y": 0, "width": 3, "height": 3, "properties": {"markdown": "v1"}}]}
    cw.put_dashboard(DashboardName=name, DashboardBody=json.dumps(body_v1), Tags=[{"Key": "k1", "Value": "v1"}])

    entries = cw.list_dashboards(DashboardNamePrefix=name)["DashboardEntries"]
    assert len(entries) == 1
    arn = entries[0]["DashboardArn"]
    assert cw.list_tags_for_resource(ResourceARN=arn)["Tags"] == [{"Key": "k1", "Value": "v1"}]

    # update: body is replaced, but a Tags value on the update call is ignored
    body_v2 = {"widgets": [{"type": "text", "x": 0, "y": 0, "width": 3, "height": 3, "properties": {"markdown": "v2"}}]}
    cw.put_dashboard(DashboardName=name, DashboardBody=json.dumps(body_v2), Tags=[{"Key": "k2", "Value": "v2"}])

    fetched = json.loads(cw.get_dashboard(DashboardName=name)["DashboardBody"])
    assert fetched["widgets"][0]["properties"]["markdown"] == "v2", "DashboardBody must be replaced on update"

    tags_after_update = cw.list_tags_for_resource(ResourceARN=arn)["Tags"]
    assert tags_after_update == [{"Key": "k1", "Value": "v1"}], (
        f"Tags on an update call must be ignored, got {tags_after_update}"
    )

    # error boundary: syntactically invalid JSON is rejected
    code, message = _error_code(lambda: cw.put_dashboard(DashboardName=name, DashboardBody="{not valid json"))
    assert code == "InvalidParameterInput", f"expected InvalidParameterInput, got {code}"
    expected_message = "The field DashboardBody must be a valid JSON object"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # the rejected call must have had no effect: the dashboard body from the last
    # successful update (v2) is still what is stored
    fetched_after_reject = json.loads(cw.get_dashboard(DashboardName=name)["DashboardBody"])
    assert fetched_after_reject["widgets"][0]["properties"]["markdown"] == "v2", (
        f"rejected PutDashboard must not change the stored body, got {fetched_after_reject}"
    )


def _safe_delete_dashboard(cw, name):
    try:
        cw.delete_dashboards(DashboardNames=[name])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
