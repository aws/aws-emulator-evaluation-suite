"""dead-letter-config-roundtrip."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "dead-letter-config-roundtrip"
GROUP = 'dlq_legacy'
SERVICES = ['lambda']


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


def _cleanup_fn(ctx, lam, name):
    try:
        lam.delete_function_url_config(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_active(lam, fn, timeout_s=60):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed":
            raise AssertionError(f"Function {fn} entered Failed: {last.get('StateReason')}")
        if last["State"] == "Active":
            return
        time.sleep(1.0)
    raise AssertionError(f"{fn} Active not met within {timeout_s}s. Last: {last!r}")


def _sqs_exec_role_arn(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-sqs-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Path="/sim2real/",
        Tags=[{"Key": "sim2real:managed", "Value": "true"},
              {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
    )["Role"]["Arn"]

    def _cleanup_role():
        for pn in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup_role)
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sqs-exec",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow",
                 "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                 "Resource": "arn:aws:logs:*:*:*"},
                {"Effect": "Allow",
                 "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage",
                            "sqs:GetQueueAttributes", "sqs:SendMessage"],
                 "Resource": "*"},
            ],
        }),
    )
    return arn


def _create_with_role_retry(fn, timeout_s=90, interval_s=5.0):
    """Retries the real dependent call through IAM propagation lag: either the
    trust policy not yet letting Lambda assume the role, or the inline policy not
    yet granting sqs:SendMessage on the DLQ target."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            msg = str(exc)
            transient = (
                "does not have permissions" in msg
                or "cannot be assumed" in msg
                or ("InvalidParameterValueException" in msg and "role" in msg.lower())
            )
            if transient and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeadLetterConfig set on Create persists and is returned by GetFunctionConfiguration."""
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")
    q_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda u=q_url: ctx.client("sqs").delete_queue(QueueUrl=u))
    q_arn = sqs.get_queue_attributes(QueueUrl=q_url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    fn_name = ctx.unique_name("sim2real-behav-fn-")
    # DeadLetterConfig makes Lambda validate that the execution role can call
    # sqs:SendMessage on the target at CreateFunction time; use the dedicated
    # SQS-capable role and retry through IAM propagation.
    role = _sqs_exec_role_arn(ctx)
    _create_with_role_retry(
        lambda: lam.create_function(
            FunctionName=fn_name,
            Runtime="python3.12",
            Handler="index.handler",
            Role=role,
            Code={"ZipFile": _make_zip("def handler(event, context): return event\n")},
            DeadLetterConfig={"TargetArn": q_arn},
        )
    )
    ctx.on_cleanup(lambda n=fn_name: _cleanup_fn(ctx, lam, n))
    _wait_active(lam, fn_name)
    config = lam.get_function_configuration(FunctionName=fn_name)
    actual_arn = config.get("DeadLetterConfig", {}).get("TargetArn")
    assert actual_arn == q_arn, (
        f"expected GetFunctionConfiguration to report DeadLetterConfig.TargetArn={q_arn!r} "
        f"(set at CreateFunction), got {actual_arn!r} from an independent read"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
