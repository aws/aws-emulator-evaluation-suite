"""braket-cancel-quantum-task-after-completion-conflict-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "braket-cancel-quantum-task-after-completion-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["braket"]

SV1_ARN = "arn:aws:braket:::device/quantum-simulator/amazon/sv1"

BELL_ACTION = json.dumps(
    {
        "braketSchemaHeader": {"name": "braket.ir.openqasm.program", "version": "1"},
        "source": (
            "OPENQASM 3.0; bit[2] b; qubit[2] q; h q[0]; cnot q[0], q[1]; "
            "b[0] = measure q[0]; b[1] = measure q[1];"
        ),
    }
)


def _slow_action_source(n_qubits: int = 26, layers: int = 30) -> str:
    body = [f"bit[{n_qubits}] b;", f"qubit[{n_qubits}] q;"]
    for _ in range(layers):
        body += [f"h q[{i}];" for i in range(n_qubits)]
        body += [f"cnot q[{i}], q[{i + 1}];" for i in range(n_qubits - 1)]
    body += [f"b[{i}] = measure q[{i}];" for i in range(n_qubits)]
    return "OPENQASM 3.0; " + " ".join(body)


# Deep enough to keep SV1 simulating for several seconds -- long enough that a cancel issued
# right after creation can land on the task before it reaches COMPLETED (a 2-qubit Bell circuit
# completes faster than the create+cancel round trip, so cancelling it never wins the race).
SLOW_ACTION = json.dumps(
    {
        "braketSchemaHeader": {"name": "braket.ir.openqasm.program", "version": "1"},
        "source": _slow_action_source(),
    }
)


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CancelQuantumTask on an already-COMPLETED task is rejected with ConflictException; a
    freshly-created, still-pending task can still be cancelled (positive control, same op).
    """
    braket = ctx.client("braket")
    try:
        braket.get_device(deviceArn=SV1_ARN)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            raise AssertionError(f"SV1 simulator device is not exposed in region {ctx.region}")
        raise

    _ensure_braket_service_linked_role(ctx)
    bucket = _create_output_bucket(ctx)

    # Task A: let it fully complete, then try (and fail) to cancel it.
    arn_a = _create_task_once_role_visible(
        lambda: braket.create_quantum_task(
            clientToken=ctx.unique_name("sim2real-conflict-a-"),
            deviceArn=SV1_ARN,
            action=BELL_ACTION,
            shots=10,
            outputS3Bucket=bucket,
            outputS3KeyPrefix="results-a",
            tags={"sim2real-check": "cancel-conflict-a"},
        )
    )["quantumTaskArn"]
    ctx.on_cleanup(lambda: _best_effort_cancel(ctx, braket, arn_a))

    task_a = _poll_until(
        lambda: braket.get_quantum_task(quantumTaskArn=arn_a),
        lambda t: t["status"] in ("COMPLETED", "FAILED", "CANCELLED"),
        timeout_s=180,
        interval_s=3,
    )
    assert task_a["status"] == "COMPLETED", f"task A ended in {task_a['status']}, expected COMPLETED"

    err = _client_error(
        lambda: braket.cancel_quantum_task(
            quantumTaskArn=arn_a, clientToken=ctx.unique_name("sim2real-cancel-a-")
        )
    )
    assert err["Code"] == "ConflictException", f"expected ConflictException, got {err!r}"
    expected = (
        "Amazon Braket cannot cancel a quantum task in the COMPLETED status for device ARN "
        f"{SV1_ARN}."
    )
    assert err["Message"] == expected, f"expected message {expected!r}, got {err['Message']!r}"

    # Effect absent: the completed task's status is untouched by the rejected cancel attempt.
    still = braket.get_quantum_task(quantumTaskArn=arn_a)
    assert still["status"] == "COMPLETED"

    # Positive control: cancelling a brand-new, not-yet-terminal task with the same operation
    # succeeds. Acceptance (200, CANCELLING/CANCELLED) starts an async cancellation that can
    # still lose the race to a fast simulator's own completion -- confirmed on real AWS, where
    # an accepted cancel was followed by COMPLETED. Retry the create+cancel-immediately race
    # until it demonstrably lands on CANCELLED once; a target whose CancelQuantumTask never
    # actually stops a task fails every attempt instead of just losing the occasional race.
    task_b = None
    for attempt in range(8):
        arn_b = braket.create_quantum_task(
            clientToken=ctx.unique_name(f"sim2real-conflict-b{attempt}-"),
            deviceArn=SV1_ARN,
            action=SLOW_ACTION,
            shots=10,
            outputS3Bucket=bucket,
            outputS3KeyPrefix=f"results-b{attempt}",
            tags={"sim2real-check": "cancel-conflict-b"},
        )["quantumTaskArn"]
        ctx.on_cleanup(lambda arn=arn_b: _best_effort_cancel(ctx, braket, arn))

        cancel_resp = braket.cancel_quantum_task(
            quantumTaskArn=arn_b, clientToken=ctx.unique_name(f"sim2real-cancel-b{attempt}-")
        )
        assert cancel_resp["cancellationStatus"] in ("CANCELLING", "CANCELLED"), (
            f"attempt {attempt}: expected CANCELLING/CANCELLED, got "
            f"{cancel_resp['cancellationStatus']!r}"
        )

        candidate = _poll_until(
            lambda arn=arn_b: braket.get_quantum_task(quantumTaskArn=arn),
            lambda t: t["status"] in ("CANCELLED", "COMPLETED", "FAILED"),
            timeout_s=120,
            interval_s=3,
        )
        if candidate["status"] == "CANCELLED":
            task_b = candidate
            break

    assert task_b is not None, "CancelQuantumTask never cancelled a non-terminal task in 8 attempts"
    assert task_b["status"] == "CANCELLED"


def _ensure_braket_service_linked_role(ctx) -> None:
    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="braket.amazonaws.com")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInput":
            raise


def _create_task_once_role_visible(create, timeout_s: float = 180.0, interval_s: float = 10.0):
    """Create the first quantum task once Braket sees the service-linked role.

    A service-linked role created moments ago takes a while to reach Braket, which refuses
    with AccessDeniedException naming the missing role until then; retry only that refusal,
    bounded by timeout_s.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return create()
        except ClientError as exc:
            err = exc.response["Error"]
            propagating = (
                err["Code"] == "AccessDeniedException"
                and "AWSServiceRoleForAmazonBraket role doesn't exist" in err.get("Message", "")
            )
            if not propagating or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _create_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("amazon-braket-sim2real-").lower().replace("_", "-")
    if ctx.region == "us-east-1":  # CreateBucket rejects LocationConstraint for this one region
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name) -> None:
    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _best_effort_cancel(ctx, braket, task_arn) -> None:
    try:
        braket.cancel_quantum_task(
            quantumTaskArn=task_arn, clientToken=ctx.unique_name("sim2real-cleanup-cancel-")
        )
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] in ("ResourceNotFoundException",)
            or (exc.response["Error"]["Code"] == "ConflictException" and "cannot cancel a quantum task in the" in exc.response["Error"].get("Message", ""))
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
