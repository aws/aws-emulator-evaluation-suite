"""deploy-metric-filter-cfn-then-emits-metric-datapoint."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-metric-filter-cfn-then-emits-metric-datapoint"
GROUP = "deploy"
SERVICES = ["logs"]

_TERMINAL_STACK_STATUSES = {
    "CREATE_COMPLETE",
    "ROLLBACK_COMPLETE",
    "ROLLBACK_FAILED",
    "CREATE_FAILED",
}


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::Logs::MetricFilter actually emits a CloudWatch metric
    datapoint when a matching log event is ingested, not merely a describable filter resource."""
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")

    group_name = ctx.unique_name("sim2real-behav-logs-mf-group-")
    stream_name = ctx.unique_name("sim2real-behav-logs-mf-stream-")
    filter_name = ctx.unique_name("sim2real-behav-logs-mf-filter-")
    stack_name = ctx.unique_name("sim2real-behav-logs-mf-stack-")
    namespace = ctx.unique_name("Sim2RealBehav/LogsMF/")
    metric_name = "ErrorCount"

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "LogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {"LogGroupName": group_name, "RetentionInDays": 1},
            },
            "LogStream": {
                "Type": "AWS::Logs::LogStream",
                "Properties": {
                    "LogGroupName": {"Ref": "LogGroup"},
                    "LogStreamName": stream_name,
                },
            },
            "MetricFilter": {
                "Type": "AWS::Logs::MetricFilter",
                "Properties": {
                    "LogGroupName": {"Ref": "LogGroup"},
                    "FilterName": filter_name,
                    "FilterPattern": "ERROR",
                    "MetricTransformations": [
                        {
                            "MetricName": metric_name,
                            "MetricNamespace": namespace,
                            "MetricValue": "1",
                            "DefaultValue": 0,
                        }
                    ],
                },
            },
        },
    }

    cfn.create_stack(StackName=stack_name, TemplateBody=json.dumps(template))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    status = _wait_stack_terminal(cfn, stack_name, timeout_s=300, interval_s=10)
    assert status == "CREATE_COMPLETE", f"stack did not reach CREATE_COMPLETE, got {status}"

    described = logs.describe_metric_filters(logGroupName=group_name, filterNamePrefix=filter_name)
    filters = described["metricFilters"]
    assert len(filters) == 1
    assert filters[0]["filterPattern"] == "ERROR"
    assert filters[0]["metricTransformations"][0]["metricNamespace"] == namespace
    assert filters[0]["metricTransformations"][0]["metricName"] == metric_name

    now_ms = int(time.time() * 1000)
    logs.put_log_events(
        logGroupName=group_name,
        logStreamName=stream_name,
        logEvents=[
            {"timestamp": now_ms, "message": "INFO: nothing to see here"},
            {"timestamp": now_ms + 1, "message": "ERROR: disk is on fire"},
        ],
    )

    total_sum = _poll_metric_sum(cw, namespace, metric_name, timeout_s=300, interval_s=10)
    if total_sum is None:
        raise AssertionError(
            "no CloudWatch metric datapoint appeared for the CFN-deployed metric filter within "
            "the 300s polling budget; real CloudWatch Logs->metrics ingestion latency can exceed "
            "this window on some accounts/regions"
        )
    assert total_sum == 1, f"expected Sum=1 for the single matching event, got sum={total_sum}"


def _wait_stack_terminal(cfn: Any, stack_name: str, timeout_s: float, interval_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    status = "UNKNOWN"
    while time.monotonic() < deadline:
        resp = cfn.describe_stacks(StackName=stack_name)
        status = resp["Stacks"][0]["StackStatus"]
        if status in _TERMINAL_STACK_STATUSES:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach a terminal state, last seen {status}")


def _delete_stack(cfn: Any, stack_name: str) -> None:
    try:
        cfn.delete_stack(StackName=stack_name)
        waiter = cfn.get_waiter("stack_delete_complete")
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


def _poll_metric_sum(cw: Any, namespace: str, metric_name: str, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        end = datetime.now(timezone.utc) + timedelta(minutes=1)
        start = end - timedelta(minutes=15)
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=start,
            EndTime=end,
            Period=60,
            Statistics=["Sum"],
        )
        datapoints = resp.get("Datapoints", [])
        if datapoints:
            return sum(dp["Sum"] for dp in datapoints)
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
