"""deploy-app-monitor-cfn-stack-behaves."""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "deploy-app-monitor-cfn-stack-behaves"
GROUP = "deploy"
SERVICES = ["rum"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An AWS::RUM::AppMonitor deployed via CloudFormation accepts PutRumEvents traffic
    and GetAppMonitor reflects the templated configuration, beyond CREATE_COMPLETE: a page
    view sent with the documented event metadata surfaces through GetAppMonitorData."""
    cfn = ctx.client("cloudformation")
    rum = ctx.client("rum")

    stack_name = ctx.unique_name("sim2real-behav-rum-stack-")
    app_name = ctx.unique_name("sim2real-behav-rum-cfnapp-")
    template = {
        "Resources": {
            "AppMonitor": {
                "Type": "AWS::RUM::AppMonitor",
                "Properties": {
                    "Name": app_name,
                    "Domain": "example.com",
                    "CwLogEnabled": False,
                    "AppMonitorConfiguration": {
                        "AllowCookies": True,
                        "SessionSampleRate": 1,
                        "Telemetries": ["errors", "performance"],
                    },
                    "Tags": [{"Key": "sim2real-env", "Value": "behavioral"}],
                },
            }
        },
        "Outputs": {
            "AppMonitorId": {"Value": {"Fn::GetAtt": ["AppMonitor", "Id"]}},
        },
    }

    cfn.create_stack(StackName=stack_name, TemplateBody=json.dumps(template))
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))

    status = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s in ("CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"),
        timeout_s=60.0,
        interval_s=5.0,
    )
    assert status == "CREATE_COMPLETE", f"stack did not reach CREATE_COMPLETE, got {status}"

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    }
    app_id = outputs["AppMonitorId"]

    monitor = rum.get_app_monitor(Name=app_name)["AppMonitor"]
    assert monitor["Domain"] == "example.com", monitor["Domain"]
    assert monitor["Id"] == app_id, (monitor["Id"], app_id)
    assert monitor["AppMonitorConfiguration"]["SessionSampleRate"] == 1, monitor["AppMonitorConfiguration"]
    assert monitor["AppMonitorConfiguration"]["AllowCookies"] is True, monitor["AppMonitorConfiguration"]
    assert set(monitor["AppMonitorConfiguration"]["Telemetries"]) == {"errors", "performance"}, (
        monitor["AppMonitorConfiguration"]
    )

    # The deployed app monitor must actually accept and surface telemetry, not just return
    # a 200 on PutRumEvents -- confirm the event is independently readable via
    # GetAppMonitorData, the consumer-side read, before declaring the pipeline live.
    # The RUM event schema ("Information collected by the CloudWatch RUM web client") gives
    # every event metadata whose schema version is 1.0.0 and whose domain is the monitored
    # application's URL domain, and a page view's details carry its page id. RUM ingests an
    # event of that shape; this one is a page view of the app monitor's own domain.
    event_id = str(uuid.uuid4())
    page_id = "/cfn-deploy-check"
    put_at_ms = int(time.time() * 1000)
    rum.put_rum_events(
        Id=app_id,
        BatchId=str(uuid.uuid4()),
        AppMonitorDetails={"id": app_id, "name": app_name, "version": "1.0"},
        UserDetails={"sessionId": str(uuid.uuid4()), "userId": str(uuid.uuid4())},
        RumEvents=[
            {
                "id": event_id,
                "timestamp": datetime.now(timezone.utc),
                "type": "com.amazon.rum.page_view_event",
                "metadata": json.dumps({"version": "1.0.0", "domain": "example.com", "pageId": page_id}),
                "details": json.dumps({"version": "1.0.0", "pageId": page_id}),
            }
        ],
    )

    # RUM documents no ingestion latency; an event of this shape surfaces within about a minute,
    # so 220 s (bounded by the check's own budget) leaves several times that.
    budget = 220.0 if ctx.time_left() is None else min(220.0, max(ctx.time_left() - 30.0, 0.0))
    event = _poll_for_event(rum, app_name, event_id, after_ms=put_at_ms - 300_000,
                            timeout_s=budget, interval_s=10.0)
    assert event is not None, (
        f"event {event_id} submitted via PutRumEvents against the CFN-deployed app monitor "
        f"{app_name!r} never surfaced via GetAppMonitorData within {budget:.0f}s -- the "
        "control-plane assertions above already confirmed the resource is real and configured, "
        "so this isolates a data-plane ingestion gap specifically."
    )
    assert event.get("event_type") == "com.amazon.rum.page_view_event", event.get("event_type")
    assert event.get("application_id") == app_id, (event.get("application_id"), app_id)
    assert (event.get("metadata") or {}).get("domain") == "example.com", event.get("metadata")
    assert (event.get("event_details") or {}).get("pageId") == page_id, event.get("event_details")


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _poll_for_event(rum, monitor_name: str, event_id: str, *, after_ms: int, timeout_s: float,
                    interval_s: float) -> dict | None:
    """The raw GetAppMonitorData event whose event_id is ``event_id``, or None at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        next_token = None
        while True:
            kwargs = {
                "Name": monitor_name,
                "TimeRange": {"After": after_ms, "Before": int(time.time() * 1000) + 60_000},
                "MaxResults": 100,
            }
            if next_token:
                kwargs["NextToken"] = next_token
            resp = rum.get_app_monitor_data(**kwargs)
            for raw_event in resp.get("Events", []):
                event = json.loads(raw_event)
                if event.get("event_id") == event_id:
                    return event
            next_token = resp.get("NextToken")
            if not next_token:
                break
        if time.monotonic() + interval_s > deadline:
            return None
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
