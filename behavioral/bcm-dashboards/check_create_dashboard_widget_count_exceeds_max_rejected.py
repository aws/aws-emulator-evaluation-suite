"""create-dashboard-widget-count-exceeds-max-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-dashboard-widget-count-exceeds-max-rejected"
GROUP = "overly-permissive"
SERVICES = ["bcm-dashboards"]

_TAGS = [{"key": "sim2real", "value": "widget-count-exceeds-max"}]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDashboard rejects a widgets list of 21 entries (the documented max is 20)
    with ValidationException, and no dashboard is created; a request at exactly the
    boundary (20 widgets) succeeds in the same file."""
    bcm = ctx.client("bcm-dashboards")

    over_name = ctx.unique_name("sim2real-dash-")
    too_many_widgets = [_cost_widget(f"Widget {i}") for i in range(21)]
    try:
        over_resp = bcm.create_dashboard(name=over_name, widgets=too_many_widgets, resourceTags=_TAGS)
    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = err.response["Error"].get("Message")
    else:
        ctx.on_cleanup(lambda: bcm.delete_dashboard(arn=over_resp["arn"]))
        raise AssertionError(
            f"real AWS rejects a 21-widget CreateDashboard, but it SUCCEEDED and returned {over_resp!r}"
        )
    assert code == "ValidationException", code
    # AWS answers this validation error with the rejected value quoted or with it left out.
    constraint = "at 'widgets' failed to satisfy constraint: Member must have length less than or equal to 20"
    quoted, unquoted = (
        "1 validation error detected: Value '["
        + ", ".join(_widget_repr(f"Widget {i}") for i in range(21))
        + "]' " + constraint,
        "1 validation error detected: Value " + constraint,
    )
    expected_message = quoted if message.startswith("1 validation error detected: Value '") else unquoted
    assert message == expected_message, message

    assert over_name not in _list_all_dashboard_names(bcm), (
        "a dashboard was created despite exceeding the widget limit"
    )

    # positive control: exactly the documented maximum (20) succeeds
    ok_name = ctx.unique_name("sim2real-dash-")
    exactly_max_widgets = [_cost_widget(f"Widget {i}") for i in range(20)]
    arn = bcm.create_dashboard(name=ok_name, widgets=exactly_max_widgets, resourceTags=_TAGS)["arn"]
    ctx.on_cleanup(lambda: bcm.delete_dashboard(arn=arn))
    widget_count = len(bcm.get_dashboard(arn=arn)["widgets"])
    assert widget_count == 20, f"expected 20 widgets at the documented maximum, got {widget_count}"


def _cost_widget(title: str) -> dict:
    return {
        "title": title,
        "configs": [
            {
                "queryParameters": {
                    "costAndUsage": {
                        "metrics": ["UnblendedCost"],
                        "timeRange": {
                            "startTime": {"type": "RELATIVE", "value": "-P1M"},
                            "endTime": {"type": "RELATIVE", "value": "-P0D"},
                        },
                        "granularity": "MONTHLY",
                    }
                },
                "displayConfig": {"table": {}},
            }
        ],
    }


def _widget_repr(title: str) -> str:
    """How the service echoes one _cost_widget(title) in a constraint message."""
    return (
        "Widget(id=null, title=" + title + ", description=null, width=null, height=null, "
        "horizontalOffset=null, configs=[WidgetConfig(queryParameters=QueryParameters("
        "costAndUsage=CostAndUsageQuery(metrics=[UnblendedCost], timeRange=DateTimeRange("
        "startTime=DateTimeValue(type=RELATIVE, value=-P1M), endTime=DateTimeValue(type=RELATIVE, "
        "value=-P0D)), granularity=MONTHLY, groupBy=null, filter=null)), displayConfig="
        "DisplayConfig(table=TableDisplayConfigStruct(columnPreferences=null)))])"
    )


def _list_all_dashboard_names(bcm) -> set[str]:
    out: set[str] = set()
    token = None
    while True:
        kwargs = {"nextToken": token} if token else {}
        resp = bcm.list_dashboards(maxResults=100, **kwargs)
        out.update(d["name"] for d in resp["dashboards"])
        token = resp.get("nextToken")
        if not token:
            break
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
