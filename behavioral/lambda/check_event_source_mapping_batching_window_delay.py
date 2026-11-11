"""event-source-mapping-batching-window-delay."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "event-source-mapping-batching-window-delay"
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


def _create_function_with_role_propagation_retry(lam, kwargs, timeout_s=90, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if (code == "InvalidParameterValueException"
                    and "cannot be assumed" in str(exc)
                    and time.monotonic() < deadline):
                time.sleep(interval_s)
                continue
            raise


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
    _create_function_with_role_propagation_retry(lam, kwargs)
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
            if "does not have permissions" in str(exc) and time.monotonic() < deadline:
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


def _poll_until(probe, predicate, *, timeout_s=90, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """MaximumBatchingWindowInSeconds is configurable and consistently queryable end-to-end."""
    lam = ctx.client("lambda")
    fn = _deploy_function(ctx, lam, "def handler(e, c): return {'ok': True}", role=_sqs_exec_role_arn(ctx))
    _, queue_arn = _make_sqs_source(ctx)

    esm = _create_with_role_retry(
        lambda: lam.create_event_source_mapping(
            FunctionName=fn,
            EventSourceArn=queue_arn,
            BatchSize=10,
            MaximumBatchingWindowInSeconds=30,
            Enabled=True,
        )
    )
    uuid_ = esm["UUID"]

    def _delete_if_present():
        try:
            lam.delete_event_source_mapping(UUID=uuid_)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_delete_if_present)
    assert esm.get("MaximumBatchingWindowInSeconds") == 30, esm

    created = _poll_until(
        lambda: lam.get_event_source_mapping(UUID=uuid_),
        lambda r: r.get("State") not in (None, "Creating"),
        timeout_s=90,
        interval_s=3.0,
        description=f"event source mapping {uuid_} to leave Creating",
    )
    assert created["MaximumBatchingWindowInSeconds"] == 30, created

    updated = lam.update_event_source_mapping(UUID=uuid_, MaximumBatchingWindowInSeconds=5)
    assert updated["MaximumBatchingWindowInSeconds"] == 5, updated

    reflected = _poll_until(
        lambda: lam.get_event_source_mapping(UUID=uuid_),
        lambda r: r.get("MaximumBatchingWindowInSeconds") == 5,
        timeout_s=90,
        interval_s=3.0,
        description=f"event source mapping {uuid_} batching-window update to be reflected",
    )
    assert reflected["MaximumBatchingWindowInSeconds"] == 5, reflected

    listed = lam.get_event_source_mapping(UUID=uuid_)
    assert listed["UUID"] == uuid_, listed
    assert listed["MaximumBatchingWindowInSeconds"] == 5, listed

    def _delete_once_settled():
        deadline = time.monotonic() + 90
        while True:
            try:
                lam.delete_event_source_mapping(UUID=uuid_)
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "ResourceInUseException" and time.monotonic() < deadline:
                    time.sleep(3.0)
                    continue
                raise

    _delete_once_settled()

    def _read_after_delete():
        """("present", None) while the mapping is still readable, else (code, message)."""
        try:
            lam.get_event_source_mapping(UUID=uuid_)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        return "present", None

    gone_code, gone_message = _poll_until(
        _read_after_delete,
        lambda outcome: outcome[0] == "ResourceNotFoundException",
        timeout_s=90,
        interval_s=3.0,
        description=f"event source mapping {uuid_} to become not-found after delete",
    )
    assert gone_code == "ResourceNotFoundException", gone_code
    expected_gone_message = "The resource you requested does not exist."
    assert gone_message == expected_gone_message, (
        f"expected message {expected_gone_message!r} reading a deleted mapping, got {gone_message!r}"
    )

    try:
        lam.update_event_source_mapping(UUID=uuid_, MaximumBatchingWindowInSeconds=1)
    except ClientError as exc:
        dead_update_err = exc.response.get("Error", {})
    else:
        raise AssertionError(f"updating deleted mapping {uuid_} succeeded; expected ResourceNotFoundException")
    assert dead_update_err.get("Code") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException updating a deleted mapping, got {dead_update_err!r}"
    )
    expected_update_message = "The resource you requested does not exist."
    assert dead_update_err.get("Message") == expected_update_message, (
        f"expected message {expected_update_message!r} updating a deleted mapping, "
        f"got {dead_update_err.get('Message')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
