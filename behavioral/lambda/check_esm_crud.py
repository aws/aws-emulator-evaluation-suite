"""esm-crud."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "esm-crud"
GROUP = 'esm'
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


def _deploy_function(ctx, lam, code, *, name=None, handler="index.handler",
                     runtime="python3.12", memory=128, timeout=30, environment=None,
                     layers=None, ephemeral_storage=None, role):
    name = name or ctx.unique_name("sim2real-behav-fn-")
    kwargs = {
        "FunctionName": name,
        "Runtime": runtime,
        "Handler": handler,
        "Role": role,
        "Code": {"ZipFile": _make_zip(code)},
        "MemorySize": memory,
        "Timeout": timeout,
    }
    if environment:
        kwargs["Environment"] = {"Variables": environment}
    if layers:
        kwargs["Layers"] = layers
    if ephemeral_storage:
        kwargs["EphemeralStorage"] = {"Size": ephemeral_storage}
    deadline = time.monotonic() + 90
    while True:
        try:
            lam.create_function(**kwargs)
            break
        except ClientError as exc:
            if "cannot be assumed" in str(exc) and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)
    return name


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


def _delete_esm(lam, uuid_):
    try:
        lam.delete_event_source_mapping(UUID=uuid_)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_with_role_retry(fn, timeout_s=90, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if "does not have permissions" in str(exc) and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Create/Get/Delete EventSourceMapping round-trips."""
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")
    q_name = ctx.unique_name("sim2real-behav-q-")
    q_url = sqs.create_queue(QueueName=q_name)["QueueUrl"]
    ctx.on_cleanup(lambda u=q_url: ctx.client("sqs").delete_queue(QueueUrl=u))
    q_arn = sqs.get_queue_attributes(QueueUrl=q_url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    fn = _deploy_function(ctx, lam, "def handler(e, c): return {'ok': True}", role=_sqs_exec_role_arn(ctx))
    esm = _create_with_role_retry(
        lambda: lam.create_event_source_mapping(
            EventSourceArn=q_arn, FunctionName=fn, BatchSize=5, Enabled=False
        )
    )
    uuid_ = esm["UUID"]
    ctx.on_cleanup(lambda u=uuid_: _delete_esm(lam, u))
    assert esm["BatchSize"] == 5
    get = lam.get_event_source_mapping(UUID=uuid_)
    assert get["FunctionArn"].endswith(fn) or fn in get["FunctionArn"]
    lam.delete_event_source_mapping(UUID=uuid_)

    # Deletion is async: the mapping stays visible (State=Deleting) until it fully
    # disappears. Poll a bounded deadline for the independent read to 404, then prove
    # the identifier is genuinely dead by trying a mutation on it.
    deadline = time.monotonic() + 120
    gone_code = gone_msg = None
    st = None
    while time.monotonic() < deadline:
        try:
            st = lam.get_event_source_mapping(UUID=uuid_)
        except ClientError as exc:
            gone_code = exc.response["Error"]["Code"]
            gone_msg = exc.response["Error"].get("Message", "")
            break
        time.sleep(2)
    if gone_code is None:
        raise AssertionError(f"GetEventSourceMapping still returned the mapping 120s after delete: {st!r}")
    assert gone_code == "ResourceNotFoundException", (
        f"GetEventSourceMapping after delete: expected ResourceNotFoundException, got {gone_code!r}"
    )
    assert gone_msg == "The resource you requested does not exist.", f"get message: {gone_msg!r}"

    mutate_code = mutate_msg = None
    try:
        lam.update_event_source_mapping(UUID=uuid_, BatchSize=10)
    except ClientError as exc:
        mutate_code = exc.response["Error"]["Code"]
        mutate_msg = exc.response["Error"].get("Message", "")
    if mutate_code is None:
        raise AssertionError("UpdateEventSourceMapping on the deleted UUID succeeded")
    assert mutate_code == "ResourceNotFoundException", (
        f"UpdateEventSourceMapping on deleted UUID: expected ResourceNotFoundException, got {mutate_code!r}"
    )
    assert mutate_msg == "The resource you requested does not exist.", f"update message: {mutate_msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
