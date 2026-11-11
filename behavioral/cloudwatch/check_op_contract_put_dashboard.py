"""op-contract-putDashboard."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "op-contract-putDashboard"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutDashboard round-trips a valid body with no validation messages; malformed JSON is rejected and leaves it unchanged."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-cwdash2-")
    body = {
        "widgets": [
            {
                "type": "metric",
                "x": 0,
                "y": 0,
                "width": 6,
                "height": 6,
                "properties": {
                    "metrics": [["AWS/EC2", "CPUUtilization"]],
                    "period": 300,
                    "stat": "Average",
                    "region": ctx.region,
                    "title": "sim2real",
                },
            }
        ]
    }
    put_resp = cw.put_dashboard(
        DashboardName=name,
        DashboardBody=json.dumps(body),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_dashboards(DashboardNames=[name]))
    validation_messages = put_resp.get("DashboardValidationMessages", [])
    assert validation_messages == [], f"expected no validation messages, got {validation_messages}"

    fetched = cw.get_dashboard(DashboardName=name)
    assert fetched["DashboardName"] == name, f"expected DashboardName {name!r}, got {fetched['DashboardName']!r}"
    fetched_body = json.loads(fetched["DashboardBody"])
    assert fetched_body == body, f"expected round-tripped body {body!r}, got {fetched_body!r}"

    err, message = _error(lambda: cw.put_dashboard(DashboardName=name, DashboardBody="{not valid json"))
    assert err == "InvalidParameterInput", f"expected InvalidParameterInput, got {err}"
    expected = "The field DashboardBody must be a valid JSON object"
    assert message == expected, f"expected the exact message {expected!r}, got {message!r}"

    # a rejected malformed update must not have replaced the existing valid dashboard body
    still_there = cw.get_dashboard(DashboardName=name)
    still_there_body = json.loads(still_there["DashboardBody"])
    assert still_there_body == body, (
        f"a rejected malformed update must not replace the existing body: expected {body!r}, "
        f"got {still_there_body!r}"
    )


def _error(fn):
    """Return (code, message) of the ClientError fn raises. A SUCCESS is an AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
