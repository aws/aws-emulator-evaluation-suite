"""put-dashboard-get-dashboard-roundtrip."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "put-dashboard-get-dashboard-roundtrip"
GROUP = "control-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A well-formed PutDashboard body yields no validation messages and round-trips via
    GetDashboard and ListDashboards; after DeleteDashboards, GetDashboard is ResourceNotFound."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-behav-dash-")
    body = {
        "widgets": [
            {
                "type": "text",
                "x": 0,
                "y": 0,
                "width": 6,
                "height": 3,
                "properties": {"markdown": "# sim2real behavioral check"},
            }
        ]
    }

    put_resp = cw.put_dashboard(DashboardName=name, DashboardBody=json.dumps(body))
    ctx.on_cleanup(lambda: cw.delete_dashboards(DashboardNames=[name]))
    validation_messages = put_resp.get("DashboardValidationMessages", [])
    assert validation_messages == [], (
        f"expected no validation messages for a well-formed dashboard body, got {validation_messages}"
    )

    get_resp = cw.get_dashboard(DashboardName=name)
    assert get_resp["DashboardName"] == name, (
        f"expected DashboardName {name!r}, got {get_resp['DashboardName']!r}"
    )
    assert "DashboardArn" in get_resp and name in get_resp["DashboardArn"], (
        f"expected DashboardArn to contain {name!r}, got {get_resp.get('DashboardArn')!r}"
    )

    cw.tag_resource(ResourceARN=get_resp["DashboardArn"], Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    applied_tags = cw.list_tags_for_resource(ResourceARN=get_resp["DashboardArn"])["Tags"]
    assert {"Key": "sim2real-check", "Value": CHECK} in applied_tags, (
        f"expected the sim2real-check tag to be applied to the dashboard, got {applied_tags}"
    )

    round_tripped = json.loads(get_resp["DashboardBody"])
    assert round_tripped["widgets"][0]["properties"]["markdown"] == "# sim2real behavioral check", (
        f"expected markdown to round-trip verbatim, got {round_tripped['widgets'][0]['properties'].get('markdown')!r}"
    )
    assert round_tripped["widgets"][0]["type"] == "text", (
        f"expected widget type 'text' to round-trip, got {round_tripped['widgets'][0].get('type')!r}"
    )

    listed = cw.list_dashboards(DashboardNamePrefix=name)["DashboardEntries"]
    assert any(e["DashboardName"] == name for e in listed), (
        f"expected {name!r} in ListDashboards, got {listed}"
    )

    cw.delete_dashboards(DashboardNames=[name])
    code, message = _client_error(lambda: cw.get_dashboard(DashboardName=name))
    assert code == "ResourceNotFound", (
        f"expected ResourceNotFound for deleted dashboard {name!r}, got {code!r}"
    )
    expected_message = f"Dashboard {name} does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _client_error(fn):
    """Return the (code, message) of the ClientError fn raises; AssertionError if it succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
