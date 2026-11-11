"""delete-event-source-mapping-in-use-rejected."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-event-source-mapping-in-use-rejected"
GROUP = "error-semantics"
SERVICES = ["lambda"]

_TAGS = {"sim2real:managed": "true"}

_ARM_BATCH_SIZES = (10, 5, 10)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteEventSourceMapping on a mapping still Updating is rejected with ResourceInUseException;
    an untouched twin deletes cleanly, and the same delete succeeds once the update settles.

    Reference: https://docs.aws.amazon.com/lambda/latest/api/API_DeleteEventSourceMapping.html
    """
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")
    fn = _create_function(ctx)

    queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-esm-q-"), tags=_TAGS)[
        "QueueUrl"
    ]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    mapping = lam.create_event_source_mapping(
        EventSourceArn=queue_arn, FunctionName=fn["name"], BatchSize=5, Enabled=True
    )
    uuid_ = mapping["UUID"]
    ctx.on_cleanup(lambda: _delete_mapping_when_settled(lam, uuid_))

    _poll_until(
        lambda: lam.get_event_source_mapping(UUID=uuid_)["State"],
        lambda state: state == "Enabled",
        timeout_s=150,
        interval_s=3,
    )

    # ---- positive control: a twin mapping on the same function, left untouched, deletes cleanly ----
    twin_queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-esm-twin-q-"), tags=_TAGS
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=twin_queue_url))
    twin_queue_arn = sqs.get_queue_attributes(QueueUrl=twin_queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    twin = lam.create_event_source_mapping(
        EventSourceArn=twin_queue_arn, FunctionName=fn["name"], BatchSize=5, Enabled=True
    )
    twin_uuid = twin["UUID"]
    ctx.on_cleanup(lambda: _delete_mapping_when_settled(lam, twin_uuid))
    _poll_until(
        lambda: lam.get_event_source_mapping(UUID=twin_uuid)["State"],
        lambda state: state == "Enabled",
        timeout_s=150,
        interval_s=3,
    )
    lam.delete_event_source_mapping(UUID=twin_uuid)
    _wait_deleted(
        lam,
        twin_uuid,
        "the twin mapping (never touched by an update) should become ResourceNotFoundException "
        "after a clean delete — without this, the rejection below cannot be told apart from a "
        "target that rejects every DeleteEventSourceMapping",
    )

    # ---- break exactly one thing: start an update on the primary mapping ----
    # The delete is sent only once an independent read still shows Updating; an update that has
    # already settled is re-armed with another BatchSize.
    for batch_size in _ARM_BATCH_SIZES:
        updated = lam.update_event_source_mapping(UUID=uuid_, BatchSize=batch_size)
        assert updated["State"] == "Updating", (
            f"UpdateEventSourceMapping is expected to leave the mapping in State=Updating "
            f"immediately after the call returns, got {updated['State']!r}"
        )
        if lam.get_event_source_mapping(UUID=uuid_)["State"] == "Updating":
            break
        _poll_until(
            lambda: lam.get_event_source_mapping(UUID=uuid_)["State"],
            lambda state: state == "Enabled",
            timeout_s=150,
            interval_s=3,
        )
    else:
        raise AssertionError(
            f"no UpdateEventSourceMapping was still Updating on the next read in "
            f"{len(_ARM_BATCH_SIZES)} attempts, so no delete could be sent mid-Updating"
        )

    delete_code, delete_msg = _must_fail(
        lambda: lam.delete_event_source_mapping(UUID=uuid_), "deleting the mapping mid-Updating"
    )
    assert delete_code == "ResourceInUseException", (
        f"expected ResourceInUseException deleting a mapping mid-Updating, got {delete_code!r}"
    )
    assert delete_msg == "Cannot delete the event source mapping because it is in use.", (
        f"unexpected in-use message: {delete_msg!r}"
    )

    # ---- effect absent: an independent read shows it is still there, untouched by the rejection ----
    try:
        still_there = lam.get_event_source_mapping(UUID=uuid_)
    except ClientError as exc:
        raise AssertionError(
            f"the mapping should still exist after the rejected delete, but reading it raised "
            f"{exc.response['Error']['Code']!r}"
        ) from exc
    assert still_there["UUID"] == uuid_, (
        f"expected the read-back UUID to match {uuid_!r}, got {still_there.get('UUID')!r}"
    )

    # ---- restore: wait for Updating to settle, then the identical delete now succeeds ----
    _poll_until(
        lambda: lam.get_event_source_mapping(UUID=uuid_)["State"],
        lambda state: state != "Updating",
        timeout_s=150,
        interval_s=3,
    )
    lam.delete_event_source_mapping(UUID=uuid_)
    _wait_deleted(
        lam,
        uuid_,
        "expected the mapping to delete cleanly and become ResourceNotFoundException once "
        "Updating had settled",
    )


def _must_fail(call, description):
    try:
        call()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"{description} unexpectedly SUCCEEDED")


def _wait_deleted(lam, uuid_, message, *, timeout_s=60.0, interval_s=2.0):
    """DeleteEventSourceMapping is eventually consistent: an immediate GetEventSourceMapping can
    still return the mapping, so poll for the specific not-found code."""
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        try:
            last_state = lam.get_event_source_mapping(UUID=uuid_).get("State")
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message2 = exc.response["Error"]["Message"]
            assert code == "ResourceNotFoundException", (
                f"{message}, but reading it raised {code!r} instead"
            )
            assert message2 == "The resource you requested does not exist.", (
                f"expected the exact ResourceNotFoundException message AWS returns, got {message2!r}"
            )
            return
        time.sleep(interval_s)
    raise AssertionError(f"{message}; still readable with State={last_state!r} after {timeout_s}s")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _delete_mapping_when_settled(lam, uuid_):
    for _ in range(40):
        try:
            lam.delete_event_source_mapping(UUID=uuid_)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("ResourceInUseException", "ResourceConflictException"):
                time.sleep(2)
                continue
            if code == "ResourceNotFoundException":
                return
            raise


def _minimal_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", "def handler(event, context):\n    return {'ok': True}\n")
    return buf.getvalue()


def _create_lambda_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaSQSQueueExecutionRole",
    )

    def _cleanup():
        for arn in (
            policy_arn,
            "arn:aws:iam::aws:policy/service-role/AWSLambdaSQSQueueExecutionRole",
        ):
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _wait_active(lam, name):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        state = cfg.get("State")
        if state == "Active":
            return
        if state == "Failed":
            raise AssertionError(f"function entered Failed state: {cfg.get('StateReason')}")
        time.sleep(2)
    raise AssertionError("function did not become Active in time")


def _create_function(ctx, **overrides):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-fn-")
    role_arn = _create_lambda_role(ctx)
    kwargs = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": _minimal_zip_bytes()},
        Timeout=10,
        Tags=_TAGS,
    )
    kwargs.update(overrides)
    resp = None
    last_err = None
    for _ in range(12):
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(**kwargs)
            break
        except ClientError as e:
            last_err = e
            if e.response["Error"][
                "Code"
            ] == "InvalidParameterValueException" and "cannot be assumed" in str(e):
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_active(lam, name)
    return {"name": name, "arn": resp["FunctionArn"], "role_arn": role_arn}


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
