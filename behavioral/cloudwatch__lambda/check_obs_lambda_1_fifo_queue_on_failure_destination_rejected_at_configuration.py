"""obs-lambda-1-fifo-queue-on-failure-destination-rejected-at-configuration."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags

CHECK = "obs-lambda-1-fifo-queue-on-failure-destination-rejected-at-configuration"
GROUP = "destination-validation"
SERVICES = ["cloudwatch", "lambda"]

_RETRIES = 1
_ROLE_PROPAGATION_BUDGET_S = 120.0

_HANDLER = '''
def handler(event, context):
    raise RuntimeError("sim2real deliberate failure")
'''


@tags("cap:c1", "concern:negative-classes", "concern:eventing", "axis:rejection", "plane:control")
def run(ctx) -> None:
    """A FIFO queue is refused as an async OnFailure destination with InvalidParameterValueException
    while a standard queue is accepted; a refused update keeps the old config, a refused put creates
    none."""
    from botocore.exceptions import ClientError

    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")

    std_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-olam-cstd-")[:80],
        tags={"sim2real": "cloudwatch__lambda"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=std_url))
    fifo_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-olam-cfifo-")[:75] + ".fifo",
        Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "true"},
        tags={"sim2real": "cloudwatch__lambda"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=fifo_url))
    std_arn = _queue_arn(sqs, std_url)
    fifo_arn = _queue_arn(sqs, fifo_url)
    assert fifo_arn.endswith(".fifo"), f"FIFO queue ARN {fifo_arn!r}"

    role_arn = _role(ctx)
    role_name = role_arn.rsplit("/", 1)[1]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-olam-dest",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "sqs:SendMessage",
                        "Resource": [std_arn, fifo_arn],
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-olam-dest")
    )

    fn_a = _function(ctx, lam, role_arn, "cfga")
    fn_b = _function(ctx, lam, role_arn, "cfgb")

    # The standard queue is accepted; retrying it also waits out role propagation.
    deadline = time.monotonic() + _ROLE_PROPAGATION_BUDGET_S
    while True:
        try:
            lam.put_function_event_invoke_config(
                FunctionName=fn_a,
                MaximumRetryAttempts=_RETRIES,
                DestinationConfig={"OnFailure": {"Destination": std_arn}},
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"standard-queue OnFailure kept being refused for "
                    f"{_ROLE_PROPAGATION_BUDGET_S}s: {exc!r}"
                ) from exc
            time.sleep(5.0)
    ctx.on_cleanup(lambda: lam.delete_function_event_invoke_config(FunctionName=fn_a))
    before = lam.get_function_event_invoke_config(FunctionName=fn_a)
    assert before["DestinationConfig"]["OnFailure"]["Destination"] == std_arn, (
        f"{fn_a} OnFailure read back {before['DestinationConfig']!r}, set {std_arn}"
    )

    # Rejected update leaves the existing destination in force.
    err = _error(
        lambda: lam.update_function_event_invoke_config(
            FunctionName=fn_a, DestinationConfig={"OnFailure": {"Destination": fifo_arn}}
        )
    )
    expected = ("InvalidParameterValueException", _fifo_refusal(fifo_arn))
    assert err == expected, (
        f"UpdateFunctionEventInvokeConfig to a FIFO OnFailure returned {err!r}, expected "
        f"{expected!r}"
    )
    after = lam.get_function_event_invoke_config(FunctionName=fn_a)
    assert after["DestinationConfig"] == before["DestinationConfig"], (
        f"a rejected update changed {fn_a}'s destinations from {before['DestinationConfig']!r} "
        f"to {after['DestinationConfig']!r}"
    )
    assert after["MaximumRetryAttempts"] == _RETRIES, (
        f"a rejected update changed MaximumRetryAttempts to {after['MaximumRetryAttempts']!r}"
    )

    # Rejected put creates nothing.
    err = _error(
        lambda: lam.put_function_event_invoke_config(
            FunctionName=fn_b,
            MaximumRetryAttempts=_RETRIES,
            DestinationConfig={"OnFailure": {"Destination": fifo_arn}},
        )
    )
    if err == _SUCCEEDED:
        ctx.on_cleanup(lambda: lam.delete_function_event_invoke_config(FunctionName=fn_b))
    expected = ("InvalidParameterValueException", _fifo_refusal(fifo_arn))
    assert err == expected, (
        f"PutFunctionEventInvokeConfig with a FIFO OnFailure returned {err!r}, expected "
        f"{expected!r}"
    )
    err = _error(lambda: lam.get_function_event_invoke_config(FunctionName=fn_b))
    fn_b_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn_b}"
    expected = (
        "ResourceNotFoundException",
        f"The function {fn_b_arn}:$LATEST doesn't have an EventInvokeConfig",
    )
    assert err == expected, (
        f"GetFunctionEventInvokeConfig on {fn_b} after the refused put returned {err!r}, expected "
        f"{expected!r}; the refusal must create no config"
    )


_SUCCEEDED = "<call unexpectedly succeeded>"


def _fifo_refusal(fifo_arn: str) -> str:
    return (
        f"The provided destination config DestinationConfig(onSuccess=null, "
        f"onFailure=OnFailure(destination={fifo_arn})) is invalid."
    )


def _error(fn):
    """(code, message) of the ClientError fn raised, or the _SUCCEEDED sentinel if it succeeded."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    return _SUCCEEDED


def _queue_arn(sqs, url: str) -> str:
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]


def _zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, src in files.items():
            zf.writestr(path, src)
    return buf.getvalue()


def _role(ctx) -> str:
    """An execution role with no CloudWatch Logs permission, so no /aws/lambda/<fn> group is left."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-olam-role-")[:64]
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Tags=[{"Key": "sim2real", "Value": "cloudwatch__lambda"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _function(ctx, lam, role_arn: str, label: str, **extra) -> str:
    from botocore.exceptions import ClientError

    name = ctx.unique_name(f"sim2real-olam-{label}-")[:64]
    logs = ctx.client("logs")
    # Registered BEFORE the create so LIFO runs it AFTER delete_function.
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{name}"))
    deadline = time.monotonic() + _ROLE_PROPAGATION_BUDGET_S
    while True:
        try:
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="handler.handler",
                Code={"ZipFile": _zip({"handler.py": _HANDLER})},
                Timeout=15,
                MemorySize=128,
                Tags={"sim2real": "cloudwatch__lambda"},
                **extra,
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"CreateFunction {name} kept refusing the fresh role for "
                    f"{_ROLE_PROPAGATION_BUDGET_S}s: {exc!r}"
                ) from exc
            time.sleep(5.0)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(
        FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 60}
    )
    return name


def _reap_log_group(logs, group: str) -> None:
    """delete_function leaves the log group, and a late flush can recreate it — so delete in a
    bounded loop until a quiet read confirms it is gone."""
    from botocore.exceptions import ClientError

    for _ in range(4):
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(5.0)
        found = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
        if not any(g["logGroupName"] == group for g in found):
            return
    raise AssertionError(f"log group {group} kept reappearing after deletion")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
