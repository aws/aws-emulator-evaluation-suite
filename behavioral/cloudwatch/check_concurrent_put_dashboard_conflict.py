"""concurrent-put-dashboard-conflict."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-put-dashboard-conflict"
GROUP = "concurrency"
SERVICES = ["cloudwatch"]
_CONFLICT_MESSAGE = (
    'A resource is already in an "actionable" state that must complete before a new update can be applied or its initial state has changed.'
)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Eight concurrent PutDashboard calls replacing one existing dashboard: each is applied or
    refused with ConflictException, and GetDashboard then returns a single widget from one applied
    call, never a merge, the pre-race body or a refused call's body."""
    from botocore.exceptions import ClientError

    cw = ctx.client("cloudwatch")
    dashboard_name = ctx.unique_name("sim2real-behav-dash-")
    cw.put_dashboard(
        DashboardName=dashboard_name,
        DashboardBody=_dashboard_body("initial"),
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )
    ctx.on_cleanup(lambda: cw.delete_dashboards(DashboardNames=[dashboard_name]))

    def racer(i: int):
        try:
            cw.put_dashboard(DashboardName=dashboard_name, DashboardBody=_dashboard_body(f"round-{i}"))
            return None
        except ClientError as e:
            return e.response["Error"]["Code"], e.response["Error"].get("Message")

    n = 8
    with ThreadPoolExecutor(max_workers=n) as ex:
        results = list(ex.map(racer, range(n)))
    for r in results:
        if r is not None:
            code, message = r
            assert code == "ConflictException", f"undocumented PutDashboard refusal: {code!r} ({message!r})"
            assert message == _CONFLICT_MESSAGE, f"ConflictException message {message!r}, expected {_CONFLICT_MESSAGE!r}"
    accepted = {_markdown(f"round-{i}") for i, r in enumerate(results) if r is None}
    assert accepted, f"every concurrent PutDashboard writer was refused: {results}"

    body = json.loads(cw.get_dashboard(DashboardName=dashboard_name)["DashboardBody"])
    widgets = body.get("widgets")
    assert isinstance(widgets, list) and len(widgets) == 1, (
        f"dashboard body must be exactly one full widget after the race, not merged/corrupted, got {body!r}"
    )
    markdown = widgets[0].get("properties", {}).get("markdown")
    assert markdown in accepted, f"final dashboard body {markdown!r} is not an applied writer's body"


def _markdown(marker: str) -> str:
    return f"sim2real-behav dashboard conflict test: {marker}"


def _dashboard_body(marker: str) -> str:
    return json.dumps(
        {
            "widgets": [
                {
                    "type": "text",
                    "x": 0,
                    "y": 0,
                    "width": 6,
                    "height": 6,
                    "properties": {"markdown": _markdown(marker)},
                }
            ]
        }
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
