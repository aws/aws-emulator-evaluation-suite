"""braket-quantum-task-bell-circuit-completes-with-correct-measurement-counts."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "braket-quantum-task-bell-circuit-completes-with-correct-measurement-counts"
GROUP = "data-plane"
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


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A 100-shot Bell circuit on SV1 reaches COMPLETED, keeps its tag, is found by SearchQuantumTasks, and its S3
    results hold 100 two-bit rows that are all 00 or 11, with both outcomes present."""
    braket = ctx.client("braket")
    try:
        braket.get_device(deviceArn=SV1_ARN)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            raise AssertionError(f"SV1 simulator device is not exposed in region {ctx.region}")
        raise

    _ensure_braket_service_linked_role(ctx)

    bucket = _create_output_bucket(ctx)
    shots = 100
    resp = _create_quantum_task_with_slr_retry(
        ctx,
        braket,
        clientToken=ctx.unique_name("sim2real-bell-"),
        deviceArn=SV1_ARN,
        action=BELL_ACTION,
        shots=shots,
        outputS3Bucket=bucket,
        outputS3KeyPrefix="results",
        tags={"sim2real-check": "bell-circuit"},
    )
    task_arn = resp["quantumTaskArn"]
    ctx.on_cleanup(lambda: _best_effort_cancel(ctx, braket, task_arn))

    task = _poll_until(
        lambda: braket.get_quantum_task(quantumTaskArn=task_arn),
        lambda t: t["status"] in ("COMPLETED", "FAILED", "CANCELLED"),
        timeout_s=180,
        interval_s=3,
    )
    assert task["status"] == "COMPLETED", (
        f"task ended in {task['status']}, failureReason={task.get('failureReason')!r}"
    )
    # GetQuantumTask's docs promise numSuccessfulShots "after a successfully completed quantum
    # task", but AWS omits the key entirely on a COMPLETED SV1 task -- the S3 measurements
    # read below is the reliable, independent proof of shot count.

    tags = braket.list_tags_for_resource(resourceArn=task_arn)["tags"]
    assert tags.get("sim2real-check") == "bell-circuit", (
        f"expected tag sim2real-check=bell-circuit, got {tags!r}"
    )

    found = braket.search_quantum_tasks(
        filters=[{"name": "quantumTaskArn", "values": [task_arn], "operator": "EQUAL"}]
    )["quantumTasks"]
    assert len(found) == 1 and found[0]["quantumTaskArn"] == task_arn, (
        f"expected search to find exactly [{task_arn}], got {found!r}"
    )

    s3 = ctx.client("s3")
    key = f"{task['outputS3Directory']}/results.json"
    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    result = json.loads(body)
    measurements = result["measurements"]
    assert len(measurements) == shots, f"expected {shots} measurement rows, got {len(measurements)}"
    outcomes = set()
    for row in measurements:
        assert len(row) == 2, f"expected 2-bit measurement, got {row!r}"
        assert all(bit in (0, 1) for bit in row), f"non-binary measurement bit in {row!r}"
        assert row[0] == row[1], (
            f"Bell circuit shot not perfectly correlated (both qubits must match): {row!r}"
        )
        outcomes.add(tuple(row))
    # SV1 is a noiseless state-vector simulator: every shot of this Bell circuit collapses to
    # exactly 00 or 11, never 01/10, and with shots=100 both outcomes occurring is a near-certainty
    # (P(all-same) = 2 * 0.5^100) -- a target returning independent per-qubit bits fails this.
    assert outcomes == {(0, 0), (1, 1)}, (
        f"expected both Bell-state outcomes {{00, 11}} across {shots} shots, got {sorted(outcomes)}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _ensure_braket_service_linked_role(ctx) -> None:
    """CreateQuantumTask needs AWSServiceRoleForAmazonBraket; a fresh account has never had it
    created, and IAM answers InvalidInput if it already exists -- create-or-adopt either way."""
    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="braket.amazonaws.com")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInput":
            raise


def _create_quantum_task_with_slr_retry(ctx, braket, **kwargs):
    """A just-created AWSServiceRoleForAmazonBraket is visible in IAM immediately but Braket's own
    permission check lags behind IAM by a few seconds on a fresh account -- retry only that specific,
    self-resolving AccessDeniedException; anything else propagates immediately."""

    def _attempt():
        try:
            return braket.create_quantum_task(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "AccessDeniedException" and "AWSServiceRoleForAmazonBraket" in err.get(
                "Message", ""
            ):
                return None
            raise

    return _poll_until(_attempt, lambda resp: resp is not None, timeout_s=60, interval_s=5)


def _create_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("amazon-braket-sim2real-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
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
