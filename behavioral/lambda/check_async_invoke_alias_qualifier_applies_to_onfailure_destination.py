"""async-invoke-alias-qualifier-applies-to-onfailure-destination."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "async-invoke-alias-qualifier-applies-to-onfailure-destination"
GROUP = "invoke_async"
SERVICES = ["lambda"]

FAILING_HANDLER = """\
def handler(event, context):
    raise RuntimeError("sim2real-intentional-async-failure")
"""


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


def _poll(probe, timeout_s, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        got = probe()
        if got:
            return got
        time.sleep(interval_s)
    return None


def _wait_active(lam, fn, timeout_s=120):
    def _probe():
        cfg = lam.get_function_configuration(FunctionName=fn)
        if cfg["State"] == "Failed":
            raise AssertionError(f"{fn} entered State=Failed: {cfg.get('StateReason')}")
        return cfg if cfg["State"] == "Active" else None

    cfg = _poll(_probe, timeout_s)
    assert cfg is not None, f"{fn} did not reach State=Active within {timeout_s}s"
    return cfg


@tags(
    "axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:eventing",
    "dp:api", "plane:data",
)
def run(ctx) -> None:
    """A failed async Invoke on an alias delivers its OnFailure record with the alias-qualified
    functionArn, condition RetriesExhausted, one attempt, and the exact request payload.
    """
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")

    queue_name = ctx.unique_name("sim2real-behav-onfail-q-")
    queue_url = sqs.create_queue(QueueName=queue_name)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    role_name = ctx.unique_name("sim2real-behav-onfail-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = ctx.unique_name("sim2real-behav-onfail-pol-")
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "arn:aws:logs:*:*:*",
            },
            {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn},
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    fn_name = ctx.unique_name("sim2real-behav-onfail-fn-")
    deadline = time.monotonic() + 90
    while True:
        try:
            lam.create_function(
                FunctionName=fn_name, Runtime="python3.12", Handler="index.handler",
                Role=role_arn, Code={"ZipFile": _make_zip(FAILING_HANDLER)},
                MemorySize=128, Timeout=10,
                Tags={"sim2real:managed": "true"},
            )
            break
        except ClientError as exc:
            if "cannot be assumed" in str(exc) and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise

    def _cleanup_fn():
        # An already-absent function or log group is done; any other teardown failure raises.
        for delete in (lambda: lam.delete_function(FunctionName=fn_name),
                       lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{fn_name}")):
            try:
                delete()
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise

    ctx.on_cleanup(_cleanup_fn)
    _wait_active(lam, fn_name)

    version = lam.publish_version(FunctionName=fn_name)["Version"]
    lam.create_alias(FunctionName=fn_name, Name="live", FunctionVersion=version)

    lam.put_function_event_invoke_config(
        FunctionName=fn_name,
        Qualifier="live",
        MaximumRetryAttempts=0,
        DestinationConfig={"OnFailure": {"Destination": queue_arn}},
    )

    resp = lam.invoke(
        FunctionName=fn_name,
        Qualifier="live",
        InvocationType="Event",
        Payload=json.dumps({"probe": "sim2real"}).encode("utf-8"),
    )
    assert resp["StatusCode"] == 202, f"async Invoke should return 202, got {resp['StatusCode']!r}"

    def _receive():
        got = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        msgs = got.get("Messages")
        return msgs[0] if msgs else None

    message = _poll(_receive, timeout_s=90, interval_s=3.0)
    assert message is not None, "no message arrived on the OnFailure destination queue within 90s"

    record = json.loads(message["Body"])
    request_context = record["requestContext"]
    assert request_context["approximateInvokeCount"] == 1, (
        f"expected approximateInvokeCount == 1 with MaximumRetryAttempts=0, "
        f"got {request_context.get('approximateInvokeCount')!r}: {record!r}"
    )
    assert request_context["condition"] == "RetriesExhausted", (
        f"expected condition 'RetriesExhausted', got {request_context.get('condition')!r}: {record!r}"
    )
    function_arn = request_context["functionArn"]
    assert function_arn.endswith(f"{fn_name}:live"), (
        f"the destination record's functionArn should be qualified by the ALIAS used on invoke "
        f"('live'), not $LATEST or the version number, got {function_arn!r}"
    )
    assert record["requestPayload"] == {"probe": "sim2real"}, (
        f"expected the delivered requestPayload to be the exact payload handed to Invoke, "
        f"got {record.get('requestPayload')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
