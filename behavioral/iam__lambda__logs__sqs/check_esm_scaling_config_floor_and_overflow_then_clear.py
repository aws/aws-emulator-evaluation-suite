"""esm-scaling-config-floor-and-overflow-then-clear."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "esm-scaling-config-floor-and-overflow-then-clear"
GROUP = "esm"
SERVICES = ["iam", "lambda", "logs", "sqs"]

_HANDLER_SRC = "def handler(event, context):\n    return {'ok': True}\n"


def _zip_bytes(src: str, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, src)
    return buf.getvalue()


def _error(fn):
    """(Error.Code, Error.Message) that fn() raises; an unexpected success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it returned: {result!r}")


def _retry_while_role_not_ready(fn, deadline_s: float = 90.0, pause_s: float = 5.0):
    """A role's trust policy can lag CreateRole's response by a few seconds before Lambda
    will accept it; retry only that specific refusal, bounded."""
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            message = exc.response.get("Error", {}).get("Message", "")
            if "cannot be assumed" in message and time.monotonic() < deadline:
                time.sleep(pause_s)
                continue
            raise


def _wait_for_state(lam, function_name: str, target: str, deadline_s: float = 90.0,
                    pause_s: float = 2.0):
    deadline = time.monotonic() + deadline_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=function_name)
        if last["State"] == target:
            return last
        if last["State"] == "Failed":
            raise AssertionError(f"{function_name} entered Failed: {last.get('StateReason')!r}")
        time.sleep(pause_s)
    raise AssertionError(f"{function_name} did not reach {target!r} within {deadline_s}s: {last!r}")


def _poll_until(read, satisfied, deadline_s: float = 60.0, pause_s: float = 2.0,
                label: str = "condition"):
    deadline = time.monotonic() + deadline_s
    last = None
    while time.monotonic() < deadline:
        last = read()
        if satisfied(last):
            return last
        time.sleep(pause_s)
    raise AssertionError(f"{label} not observed within {deadline_s}s; last read was {last!r}")


def _reap_log_group(logs, log_group_name: str, reads: int = 3, pause_s: float = 5.0,
                    deadline_s: float = 180.0) -> None:
    """A buffered flush can recreate /aws/lambda/<fn> after delete_function returns; re-delete
    until several consecutive reads find it gone."""
    deadline = time.monotonic() + deadline_s
    clean_reads = 0
    while clean_reads < reads:
        present = any(
            g["logGroupName"] == log_group_name
            for g in logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"]
        )
        if present:
            clean_reads = 0
            try:
                logs.delete_log_group(logGroupName=log_group_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            clean_reads += 1
        if clean_reads < reads:
            if time.monotonic() > deadline:
                raise AssertionError(f"{log_group_name} still reappearing after {deadline_s}s")
            time.sleep(pause_s)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """CreateEventSourceMapping refuses ScalingConfig.MaximumConcurrency=1001 and leaves only
    the mapping created at the floor value 2 in ListEventSourceMappings; Update then raises
    and clears that mapping's ScalingConfig.
    """
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    sqs = ctx.client("sqs")

    queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-esmfloor-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    role_name = ctx.unique_name("sim2real-behav-esmfloor-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    poll_policy_name = "sim2real-esmfloor-poll"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=poll_policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow",
                 "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                 "Resource": "arn:aws:logs:*:*:*"},
                {"Effect": "Allow",
                 "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                 "Resource": queue_arn},
            ],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=poll_policy_name))

    function_name = ctx.unique_name("sim2real-behav-esmfloor-fn-")
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{function_name}"))
    _retry_while_role_not_ready(lambda: lam.create_function(
        FunctionName=function_name,
        Runtime="python3.12",
        Handler="index.handler",
        Role=role_arn,
        Code={"ZipFile": _zip_bytes(_HANDLER_SRC)},
        MemorySize=128,
        Timeout=15,
    ))
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))
    _wait_for_state(lam, function_name, "Active")

    floor = _retry_while_role_not_ready(lambda: lam.create_event_source_mapping(
        FunctionName=function_name,
        EventSourceArn=queue_arn,
        Enabled=False,
        ScalingConfig={"MaximumConcurrency": 2},
    ))
    floor_uuid = floor["UUID"]
    ctx.on_cleanup(lambda: lam.delete_event_source_mapping(UUID=floor_uuid))
    assert floor["ScalingConfig"]["MaximumConcurrency"] == 2, (
        f"expected the floor value 2 to be accepted and echoed on create, "
        f"got ScalingConfig {floor.get('ScalingConfig')!r}"
    )

    code, message = _error(lambda: lam.create_event_source_mapping(
        FunctionName=function_name,
        EventSourceArn=queue_arn,
        Enabled=False,
        ScalingConfig={"MaximumConcurrency": 1001},
    ))
    assert code == "ValidationException", (
        f"expected MaximumConcurrency=1001 to be refused as ValidationException, "
        f"got {code!r}: {message!r}"
    )
    expected_message = (
        "1 validation error detected: Value '1001' at 'scalingConfig.maximumConcurrency' failed "
        "to satisfy constraint: Member must have value less than or equal to 1000"
    )
    assert message == expected_message, (
        f"expected the exact constraint message for MaximumConcurrency=1001, got {message!r}"
    )

    mappings = lam.list_event_source_mappings(FunctionName=function_name)["EventSourceMappings"]
    uuids = [m["UUID"] for m in mappings]
    assert uuids == [floor_uuid], (
        f"after the refused create, ListEventSourceMappings returned {uuids!r}; "
        f"expected only the floor mapping {floor_uuid!r}"
    )

    raised = lam.update_event_source_mapping(UUID=floor_uuid, ScalingConfig={"MaximumConcurrency": 777})
    assert raised.get("ScalingConfig", {}).get("MaximumConcurrency") == 777, (
        f"expected UpdateEventSourceMapping's response to carry MaximumConcurrency=777, "
        f"got {raised.get('ScalingConfig')!r}"
    )
    raised_read = _poll_until(
        lambda: lam.get_event_source_mapping(UUID=floor_uuid),
        lambda r: r.get("ScalingConfig", {}).get("MaximumConcurrency") == 777,
        label="GetEventSourceMapping reflecting the raised MaximumConcurrency",
    )
    assert raised_read["ScalingConfig"]["MaximumConcurrency"] == 777, (
        f"independent read after raising: expected MaximumConcurrency=777, "
        f"got {raised_read.get('ScalingConfig')!r}"
    )

    cleared = lam.update_event_source_mapping(UUID=floor_uuid, ScalingConfig={})
    assert cleared.get("ScalingConfig", {}).get("MaximumConcurrency") is None, (
        f"expected UpdateEventSourceMapping's response to drop MaximumConcurrency once cleared, "
        f"got {cleared.get('ScalingConfig')!r}"
    )
    cleared_read = _poll_until(
        lambda: lam.get_event_source_mapping(UUID=floor_uuid),
        lambda r: r.get("ScalingConfig", {}).get("MaximumConcurrency") is None,
        label="GetEventSourceMapping reflecting the cleared ScalingConfig",
    )
    assert cleared_read.get("ScalingConfig", {}).get("MaximumConcurrency") is None, (
        f"independent read after clearing: expected no MaximumConcurrency, "
        f"got {cleared_read.get('ScalingConfig')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
