"""event-source-mapping-concurrent-update-conflict."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError


from behavioral_harness import tags


CHECK = "event-source-mapping-concurrent-update-conflict"
GROUP = 'esm'
SERVICES = ['lambda']

HANDLER_V1 = "def handler(event, context): return {'marker': 'v1', 'echo': event}"


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


def _deploy_function(ctx, lam, code, *, name=None, role=None):
    name = name or ctx.unique_name("sim2real-behav-fn-")
    _create_with_role_retry(lambda: lam.create_function(
        FunctionName=name,
        Runtime="python3.12",
        Handler="index.handler",
        Role=role or _exec_role_arn(ctx),
        Code={"ZipFile": _make_zip(code)},
        MemorySize=128,
        Timeout=30,
    ))
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)
    return name


def _sqs_exec_role_arn(ctx):
    """Execution role with the SQS grant an SQS event source mapping needs."""
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
    # No fixed sleep here: IAM policy propagation is bounded instead by
    # _create_with_role_retry's deadline on the ESM create call that depends on it.
    return arn


#: Both are IAM-propagation races against a role this check just created: Lambda's own
#: assume-role check racing role creation, and CreateEventSourceMapping's poll-permission
#: check racing the inline policy attach.
_ROLE_PROPAGATION_MESSAGES = ("does not have permissions", "cannot be assumed by Lambda")


def _create_with_role_retry(fn, timeout_s=90, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            msg = str(exc)
            if (
                any(m in msg for m in _ROLE_PROPAGATION_MESSAGES)
                and time.monotonic() < deadline
            ):
                time.sleep(interval_s)
                continue
            raise


def _outcome(fn):
    """Call fn(); return ("ok", None, None) on success or ("error", code, message) on a ClientError."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return "error", err.get("Code"), err.get("Message", "")
    return "ok", None, None


def _wait_esm_settled(lam, uuid_, timeout_s=90):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            st = lam.get_event_source_mapping(UUID=uuid_).get("State")
        except ClientError:
            return
        if st not in (None, "Creating", "Updating"):
            return
        time.sleep(3.0)


def _wait_deleted(lam, uuid_, timeout_s=60):
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        outcome, last_code, _ = _outcome(lambda: lam.get_event_source_mapping(UUID=uuid_))
        if outcome == "error" and last_code == "ResourceNotFoundException":
            return
        time.sleep(2.0)
    raise AssertionError(
        f"{uuid_} not ResourceNotFoundException within {timeout_s}s; last independent read gave "
        f"{last_code!r}"
    )


def _make_queue(ctx, sqs, prefix):
    q_url = sqs.create_queue(QueueName=ctx.unique_name(prefix))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=q_url))
    q_arn = sqs.get_queue_attributes(QueueUrl=q_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return q_url, q_arn


def _is_esm_role_perm_error(exc):
    """CreateEventSourceMapping validates that the function's execution role can poll the source
    (e.g. sqs:ReceiveMessage). This error means the execution role this check created lacks that
    grant (for example, the grant has not propagated yet), not an emulator fidelity finding."""
    if not isinstance(exc, ClientError):
        return False
    err = exc.response.get("Error", {})
    msg = err.get("Message", "")
    return err.get("Code") == "InvalidParameterValueException" and (
        "does not have permissions" in msg or "ReceiveMessage" in msg
    )


def _delete_esm_when_settled(lam, uuid_, timeout_s=120, interval_s=3.0):
    """Teardown delete: retry while the mapping is in transition; a mapping already gone is done."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            lam.delete_event_source_mapping(UUID=uuid_)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code in ("ResourceInUseException", "ResourceConflictException") and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Update/Delete on an ESM still mid-Creating fails with ResourceInUseException/ResourceConflictException.

    Concurrent Update/Delete on an event source mapping mid-transition (still leaving its Creating
    state) fails with ResourceInUseException/ResourceConflictException.
    """
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")
    fn = _deploy_function(ctx, lam, HANDLER_V1, role=_sqs_exec_role_arn(ctx))

    conflict_codes = {"ResourceInUseException", "ResourceConflictException"}

    # --- Race #1: Update immediately after Create ---
    _q_url1, q_arn1 = _make_queue(ctx, sqs, "sim2real-behav-esm-conflict-q-")
    try:
        esm1 = _create_with_role_retry(
            lambda: lam.create_event_source_mapping(FunctionName=fn, EventSourceArn=q_arn1, Enabled=True)
        )
    except ClientError as exc:
        if _is_esm_role_perm_error(exc):
            raise AssertionError(
                "the function execution role lacks SQS polling permissions, so no SQS event source "
                "mapping can be created to exercise the mid-transition conflict window"
            )
        raise
    uuid1 = esm1["UUID"]
    original_batch_size = esm1["BatchSize"]
    ctx.on_cleanup(lambda: _delete_esm_when_settled(lam, uuid1))

    update_outcome, update_code, update_msg = _outcome(
        lambda: lam.update_event_source_mapping(UUID=uuid1, BatchSize=5)
    )
    if update_outcome == "ok":
        _wait_esm_settled(lam, uuid1)
        raise AssertionError(
            "the ESM left Creating before the conflicting update landed; "
            "the mid-transition conflict window was not observed"
        )
    assert update_code in conflict_codes, f"expected one of {conflict_codes}, got {update_code}"
    if update_code == "ResourceInUseException":
        assert update_msg == "Cannot update the event source mapping because it is in use.", update_msg

    # Effect-absent: an independent read must show the rejected update never took hold.
    unaffected = lam.get_event_source_mapping(UUID=uuid1)
    assert unaffected["BatchSize"] == original_batch_size, (
        f"rejected update mutated state anyway: expected BatchSize={original_batch_size}, "
        f"independent read gave {unaffected['BatchSize']}"
    )

    _wait_esm_settled(lam, uuid1)

    # Restore: the identical call the conflict blocked now succeeds once Creating has cleared.
    lam.update_event_source_mapping(UUID=uuid1, BatchSize=5)
    _wait_esm_settled(lam, uuid1)
    restored = lam.get_event_source_mapping(UUID=uuid1)
    assert restored["BatchSize"] == 5, (
        f"identical update did not take effect once the ESM settled: independent read gave "
        f"BatchSize={restored['BatchSize']}"
    )

    # --- Race #2: Delete immediately after Create (distinct queue) ---
    _q_url2, q_arn2 = _make_queue(ctx, sqs, "sim2real-behav-esm-conflict-q2-")
    esm2 = _create_with_role_retry(
        lambda: lam.create_event_source_mapping(FunctionName=fn, EventSourceArn=q_arn2, Enabled=True)
    )
    uuid2 = esm2["UUID"]

    delete_outcome, delete_code, delete_msg = _outcome(
        lambda: lam.delete_event_source_mapping(UUID=uuid2)
    )
    if delete_outcome == "ok":
        # Delete succeeded immediately (transition already finished): prove it gone regardless.
        _wait_deleted(lam, uuid2)
        return
    assert delete_code in conflict_codes, f"expected one of {conflict_codes}, got {delete_code}"
    if delete_code == "ResourceInUseException":
        assert delete_msg == "Cannot delete the event source mapping because it is in use.", delete_msg
    ctx.on_cleanup(lambda: _delete_esm_when_settled(lam, uuid2))
    _wait_esm_settled(lam, uuid2)
    lam.delete_event_source_mapping(UUID=uuid2)
    _wait_deleted(lam, uuid2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
