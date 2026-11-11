"""event-source-mapping-list-ordering."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "event-source-mapping-list-ordering"
GROUP = 'esm'
SERVICES = ['lambda']


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_EXEC_ROLES: dict = {}


def _exec_role_arn(ctx):
    """Execution role this check creates for its functions, once per run."""
    cached = _EXEC_ROLES.get(id(ctx))
    if cached and cached[0] is ctx:
        return cached[1]
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    _EXEC_ROLES[id(ctx)] = (ctx, arn)
    return arn


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
                     layers=None, ephemeral_storage=None, role=None):
    name = name or ctx.unique_name("sim2real-behav-fn-")
    kwargs = {
        "FunctionName": name,
        "Runtime": runtime,
        "Handler": handler,
        "Role": role or _exec_role_arn(ctx),
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
    _create_with_role_retry(lambda: lam.create_function(**kwargs))
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


def _create_with_role_retry(fn, timeout_s=90, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            msg = str(exc)
            code = exc.response.get("Error", {}).get("Code", "")
            role_not_yet_propagated = (
                "does not have permissions" in msg
                or "cannot be assumed" in msg
                or (code == "InvalidParameterValueException" and "role" in msg.lower())
            )
            if role_not_yet_propagated and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _make_sqs_source(ctx):
    sqs = ctx.client("sqs")
    q_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=q_url))
    q_arn = sqs.get_queue_attributes(
        QueueUrl=q_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]
    return q_url, q_arn


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListEventSourceMappings returns the same order across repeated calls,
    even though that order is not creation order."""
    lam = ctx.client("lambda")
    fn = _deploy_function(ctx, lam, "def handler(e, c): return {'ok': True}", role=_sqs_exec_role_arn(ctx))

    queue_arns = []
    for _ in range(3):
        _, q_arn = _make_sqs_source(ctx)
        queue_arns.append(q_arn)

    uuids = []
    for q_arn in queue_arns:
        esm = _create_with_role_retry(
            lambda a=q_arn: lam.create_event_source_mapping(FunctionName=fn, EventSourceArn=a, Enabled=False)
        )
        ctx.on_cleanup(lambda u=esm["UUID"]: lam.delete_event_source_mapping(UUID=u))
        uuids.append(esm["UUID"])

    first = lam.list_event_source_mappings(FunctionName=fn)["EventSourceMappings"]
    second = lam.list_event_source_mappings(FunctionName=fn)["EventSourceMappings"]

    first_uuids = [m["UUID"] for m in first]
    second_uuids = [m["UUID"] for m in second]

    third = lam.list_event_source_mappings(FunctionName=fn)["EventSourceMappings"]
    third_uuids = [m["UUID"] for m in third]

    assert set(first_uuids) == set(uuids), f"expected all created ESMs present, got {first_uuids}"
    assert first_uuids == second_uuids == third_uuids, (
        "expected ListEventSourceMappings order to be stable across repeated calls, got "
        f"{first_uuids}, then {second_uuids}, then {third_uuids}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
