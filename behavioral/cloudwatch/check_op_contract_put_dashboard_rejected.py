"""op-contract-put-dashboard-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "op-contract-put-dashboard-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutDashboard stores/round-trips a valid widget body, and rejects malformed JSON without creating anything."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-behav-dash-")
    body = {
        "widgets": [
            {"type": "text", "x": 0, "y": 0, "width": 6, "height": 6, "properties": {"markdown": "# sim2real-check"}}
        ]
    }

    put_resp = cw.put_dashboard(DashboardName=name, DashboardBody=json.dumps(body))
    ctx.on_cleanup(lambda: cw.delete_dashboards(DashboardNames=[name]))
    account = ctx.client("sts").get_caller_identity()["Account"]
    cw.tag_resource(ResourceARN=f"arn:aws:cloudwatch::{account}:dashboard/{name}", Tags=[{"Key": "sim2real", "Value": "true"}])
    assert put_resp.get("DashboardValidationMessages", []) == []

    got = cw.get_dashboard(DashboardName=name)
    assert got["DashboardName"] == name
    assert got["DashboardArn"].endswith(f":dashboard/{name}")
    stored = json.loads(got["DashboardBody"])
    assert stored["widgets"][0]["properties"]["markdown"] == "# sim2real-check"
    assert stored["widgets"][0]["type"] == "text"

    # a malformed body is rejected for a brand-new dashboard name, and that name is never created
    other_name = ctx.unique_name("sim2real-behav-dash-bad-")
    code, message = _client_error(lambda: cw.put_dashboard(DashboardName=other_name, DashboardBody="{not valid json"))
    # Real CloudWatch's wire error code for this validation is "InvalidParameterInput",
    # not the "DashboardInvalidInputError" shape name.
    assert code == "InvalidParameterInput", f"expected InvalidParameterInput, got {code}"
    expected_message = 'The field DashboardBody must be a valid JSON object'
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    code2, message2 = _client_error(lambda: cw.get_dashboard(DashboardName=other_name))
    # Real CloudWatch's wire error code for a missing dashboard is "ResourceNotFound",
    # not the "DashboardNotFoundError" shape name.
    assert code2 == "ResourceNotFound", f"rejected dashboard should not exist, got {code2}"
    expected_message2 = f"Dashboard {other_name} does not exist"
    assert message2 == expected_message2, f"expected message {expected_message2!r}, got {message2!r}"


def _client_error(fn):
    """Call fn; return the (code, message) of the ClientError it raises.

    Raises AssertionError when the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
