"""deploy-app-monitor-cfn-behaves."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-app-monitor-cfn-behaves"
GROUP = "deploy"
SERVICES = ["rum"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::RUM::AppMonitor reads back its properties through
    GetAppMonitor, and PutRumEvents accepts its own id while refusing a never-issued one with
    AccessDeniedException.
    """
    name = ctx.unique_name("sim2real-rum-cfn-")
    template = f"""
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  AppMonitor:
    Type: AWS::RUM::AppMonitor
    Properties:
      Name: {name}
      Domain: localhost
      CwLogEnabled: false
      AppMonitorConfiguration:
        AllowCookies: true
        SessionSampleRate: 1
Outputs:
  AppMonitorId:
    Value: !GetAtt AppMonitor.Id
""".strip()

    outputs = _deploy_cfn(ctx, template)
    app_monitor_id = outputs["AppMonitorId"]

    rum = ctx.client("rum")
    monitor = rum.get_app_monitor(Name=name)["AppMonitor"]
    assert monitor["Id"] == app_monitor_id, (app_monitor_id, monitor["Id"])
    assert monitor["Domain"] == "localhost", monitor["Domain"]
    assert monitor["AppMonitorConfiguration"]["AllowCookies"] is True, monitor["AppMonitorConfiguration"]
    assert monitor["AppMonitorConfiguration"]["SessionSampleRate"] == 1.0, monitor["AppMonitorConfiguration"]

    # Positive control: the live app monitor accepts data-plane telemetry for its own id.
    rum.put_rum_events(**_rum_events_payload(app_monitor_id, name))

    # Negative control on the same wiring: a syntactically valid but never-issued id must
    # be rejected, not silently accepted -- otherwise the positive call above proves nothing
    # about this specific app monitor (a target that accepts every PutRumEvents call would
    # also pass the positive leg alone).
    bogus_id = str(uuid.uuid4())
    while bogus_id == app_monitor_id:
        bogus_id = str(uuid.uuid4())
    _assert_rejected(
        lambda: rum.put_rum_events(**_rum_events_payload(bogus_id, name)),
        "AccessDeniedException",
        "Caller principal does not have permissions for that resource.",
    )


def _rum_events_payload(app_monitor_id: str, name: str) -> dict:
    return {
        "Id": app_monitor_id,
        "BatchId": str(uuid.uuid4()),
        "AppMonitorDetails": {"id": app_monitor_id, "name": name, "version": "1.0.0"},
        "UserDetails": {"sessionId": str(uuid.uuid4()), "userId": str(uuid.uuid4())},
        "RumEvents": [
            {
                "id": str(uuid.uuid4()),
                "timestamp": datetime.now(timezone.utc),
                "type": "com.amazon.rum.custom_event",
                "details": json.dumps({"message": "sim2real-cfn-check"}),
                "metadata": json.dumps({"version": "1.0.0", "domain": "localhost"}),
            }
        ],
    }


def _deploy_cfn(ctx, template_body: str) -> dict:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-rum-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Tags=[{"Key": "sim2real", "Value": "deploy-app-monitor-cfn-behaves"}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert stack["StackStatus"] == "CREATE_COMPLETE", stack["StackStatus"]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _delete_stack(cfn, stack_name: str) -> None:
    try:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 28}
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackNotFoundException":
            raise


def _assert_rejected(fn, expected_code: str, expected_message: str) -> None:
    try:
        fn()
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == expected_code, (
            f"expected {expected_code!r}, got {code!r}"
        )
        message = exc.response["Error"].get("Message")
        assert message == expected_message, (
            f"expected message {expected_message!r}, got {message!r}"
        )
    else:
        raise AssertionError(
            f"expected the call to raise {expected_code!r}, but it succeeded"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
