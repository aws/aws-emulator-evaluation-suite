"""cloudcontrol-delete-resource-removes-the-native-log-group-not-just-the-index."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cloudcontrol-delete-resource-removes-the-native-log-group-not-just-the-index"
GROUP = 'native-truth'
SERVICES = ['cloudcontrol']
LOG_GROUP_TYPE = "AWS::Logs::LogGroup"
TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
STREAM = "sim2real-behav-stream"


def _poll_until(probe, predicate, *, timeout_s=120, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _wait_terminal(cc, request_token, *, timeout_s=120, interval_s=2.0):
    """Poll GetResourceRequestStatus to a terminal OperationStatus; return the ProgressEvent."""
    return _poll_until(
        lambda: cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"],
        lambda e: e is not None and e.get("OperationStatus") in TERMINAL_STATUSES,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"request {request_token} reaching a terminal OperationStatus",
    )


def _error_code(fn):
    """The AWS error code and message raised by fn(); raises if the call unexpectedly SUCCEEDS."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"the call was expected to fail but returned {result!r}")


def _handler_not_found(message, detail):
    """Whether message is the handler's NotFound refusal; its trailing RequestToken is server-chosen."""
    prefix = f"{detail} (HandlerErrorCode: NotFound, RequestToken: "
    return message.startswith(prefix) and message.endswith(")")


def _delete_log_group_quiet(logs, name):
    try:
        logs.delete_log_group(logGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """DeleteResource on a live log group removes it from CloudWatch Logs: it is absent from a
    paginated DescribeLogGroups, PutLogEvents and GetResource both raise ResourceNotFound."""
    cc = ctx.client("cloudcontrol")
    logs = ctx.client("logs")
    name = ctx.unique_name("sim2real-behav-cclg-")

    resp = cc.create_resource(
        TypeName=LOG_GROUP_TYPE,
        DesiredState=json.dumps({
            "LogGroupName": name, "RetentionInDays": 1,
            "Tags": [{"Key": "sim2real", "Value": CHECK}],
        }),
    )
    ctx.on_cleanup(lambda: _delete_log_group_quiet(logs, name))
    create_event = _wait_terminal(cc, resp["ProgressEvent"]["RequestToken"])
    assert create_event["OperationStatus"] == "SUCCESS", f"create did not succeed: {create_event!r}"

    # Prove the group is live before the delete, so the later ResourceNotFoundException cannot
    # mean it never existed.
    logs.create_log_stream(logGroupName=name, logStreamName=STREAM)
    ingest_before = logs.put_log_events(
        logGroupName=name, logStreamName=STREAM,
        logEvents=[{"timestamp": int(time.time() * 1000), "message": "alive-before-delete"}],
    )
    assert ingest_before["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"native ingestion into the Cloud Control-created group failed: {ingest_before!r}"
    )

    deleted = cc.delete_resource(TypeName=LOG_GROUP_TYPE, Identifier=name)
    delete_event = _wait_terminal(cc, deleted["ProgressEvent"]["RequestToken"])
    assert delete_event["OperationStatus"] == "SUCCESS", f"delete did not succeed: {delete_event!r}"

    all_group_names = []
    for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=name):
        all_group_names.extend(g["logGroupName"] for g in page["logGroups"])
    assert name not in all_group_names, (
        f"the log group is still in the CloudWatch Logs inventory after DeleteResource: "
        f"{sorted(all_group_names)!r}"
    )

    code, message = _error_code(lambda: logs.put_log_events(
        logGroupName=name, logStreamName=STREAM,
        logEvents=[{"timestamp": int(time.time() * 1000), "message": "after-delete"}],
    ))
    assert code == "ResourceNotFoundException", (
        f"native ingestion after DeleteResource raised {code!r}, so the group still accepts writes"
    )
    assert message == "The specified log group does not exist.", message

    cc_code, cc_message = _error_code(lambda: cc.get_resource(TypeName=LOG_GROUP_TYPE, Identifier=name))
    assert cc_code == "ResourceNotFoundException", f"GetResource after delete raised {cc_code!r}"
    assert _handler_not_found(
        cc_message,
        f"{LOG_GROUP_TYPE} Handler returned status FAILED: Resource of type '{LOG_GROUP_TYPE}' with "
        f"identifier '{{\"/properties/LogGroupName\":\"{name}\"}}' was not found.",
    ), cc_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
