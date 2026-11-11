"""deploy-app-monitor-via-cloudformation-then-behaves."""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "deploy-app-monitor-via-cloudformation-then-behaves"
GROUP = "deploy"
SERVICES = ["rum"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  AppMonitorName:
    Type: String
Resources:
  AppMonitor:
    Type: AWS::RUM::AppMonitor
    Properties:
      Name: !Ref AppMonitorName
      Domain: example.com
      CwLogEnabled: false
Outputs:
  MonitorName:
    Value: !Ref AppMonitor
  MonitorId:
    Value: !GetAtt AppMonitor.Id
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed AWS::RUM::AppMonitor must actually accept PutRumEvents and serve
    GetAppMonitorData, not just reach CREATE_COMPLETE (the classic control-plane-only stub)."""
    cfn = ctx.client("cloudformation")
    rum = ctx.client("rum")
    stack_name = ctx.unique_name("sim2real-rum-cfn-")
    monitor_name = ctx.unique_name("sim2real-rum-mon-")

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=[{"ParameterKey": "AppMonitorName", "ParameterValue": monitor_name}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 30}
    )

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    }
    assert outputs["MonitorName"] == monitor_name, (
        f"expected stack output MonitorName={monitor_name!r}, got {outputs.get('MonitorName')!r}"
    )
    monitor_id = outputs["MonitorId"]

    # Confirm the stack actually provisioned a real, queryable app monitor (control plane).
    monitor = rum.get_app_monitor(Name=monitor_name)["AppMonitor"]
    assert monitor["Id"] == monitor_id, (
        f"expected GetAppMonitor Id to match the CFN-reported Id {monitor_id!r}, got {monitor['Id']!r}"
    )
    assert monitor["State"] == "CREATED", (
        f"expected a freshly created app monitor to report State='CREATED', got {monitor['State']!r}"
    )

    # Now exercise the data plane: send a telemetry event through the CFN-created monitor
    # and confirm it is actually ingested and later retrievable, not merely accepted with a 200.
    batch_id = str(uuid.uuid4())
    event_id = str(uuid.uuid4())
    rum.put_rum_events(
        Id=monitor_id,
        BatchId=batch_id,
        AppMonitorDetails={"id": monitor_id, "name": monitor_name, "version": "1.0.0"},
        UserDetails={"sessionId": str(uuid.uuid4()), "userId": str(uuid.uuid4())},
        RumEvents=[
            {
                "id": event_id,
                "timestamp": datetime.now(timezone.utc),
                "type": "com.amazon.rum.page_view_event",
                "metadata": json.dumps({"version": "1.0.0", "domain": "example.com"}),
                "details": json.dumps({"version": "1.0.0", "pageId": "/cfn-behavioral-check"}),
            }
        ],
    )

    found = _poll_for_event(ctx, monitor_name, event_id, timeout_s=220.0, interval_s=15.0)
    if not found:
        raise AssertionError(
            f"event {event_id} submitted via PutRumEvents never surfaced via "
            "GetAppMonitorData within the poll window; the RUM data-plane ingestion "
            "pipeline may have latency beyond what this check budgets. The control-plane "
            "assertions above (CFN-provisioned AppMonitor is real and queryable, and "
            "PutRumEvents was accepted) already confirm the resource is not a stub."
        )


def _poll_for_event(ctx, monitor_name: str, event_id: str, *, timeout_s: float, interval_s: float) -> bool:
    rum = ctx.client("rum")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        now_ms = int(time.time() * 1000)
        next_token = None
        while True:
            kwargs = {
                "Name": monitor_name,
                "TimeRange": {"After": now_ms - 3_600_000, "Before": now_ms + 3_600_000},
                "MaxResults": 100,
            }
            if next_token:
                kwargs["NextToken"] = next_token
            resp = rum.get_app_monitor_data(**kwargs)
            for raw_event in resp.get("Events", []):
                if event_id in raw_event:
                    return True
            next_token = resp.get("NextToken")
            if not next_token:
                break
        time.sleep(interval_s)
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
