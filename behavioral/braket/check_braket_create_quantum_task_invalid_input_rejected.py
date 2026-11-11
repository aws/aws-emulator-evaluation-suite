"""braket-create-quantum-task-invalid-input-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "braket-create-quantum-task-invalid-input-rejected"
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


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateQuantumTask fails with ValidationException and its exact message for an inaccessible output bucket,
    a malformed action and shots above SV1's reported maximum, while the same request with nothing broken succeeds."""
    braket = ctx.client("braket")
    _ensure_braket_service_linked_role(ctx)
    try:
        device = braket.get_device(deviceArn=SV1_ARN)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            raise AssertionError(f"SV1 simulator device is not exposed in region {ctx.region}")
        raise
    capabilities = json.loads(device["deviceCapabilities"])
    min_shots, max_shots = capabilities["service"]["shotsRange"]

    bucket = _create_output_bucket(ctx)

    # Break #1: a bucket that is syntactically fine but the caller never created/has no access to.
    err = _client_error_past_slr_propagation(
        lambda: braket.create_quantum_task(
            clientToken=ctx.unique_name("sim2real-bad-access-"),
            deviceArn=SV1_ARN,
            action=BELL_ACTION,
            shots=10,
            outputS3Bucket=ctx.unique_name("amazon-braket-sim2real-ghost-"),
            outputS3KeyPrefix="results",
        )
    )
    assert err["Code"] == "ValidationException", f"inaccessible bucket: expected ValidationException, got {err!r}"
    expected = (
        "Caller doesn't have access to bucket or it doesn't exist. Learn more on our developer "
        "guide: https://docs.aws.amazon.com/braket/latest/developerguide/braket-slr.html"
    )
    assert err["Message"] == expected, f"inaccessible bucket: expected {expected!r}, got {err['Message']!r}"

    # Break #2: action JSON missing the required braketSchemaHeader/source structure.
    err = _client_error(
        lambda: braket.create_quantum_task(
            clientToken=ctx.unique_name("sim2real-bad-action-"),
            deviceArn=SV1_ARN,
            action=json.dumps({"foo": "bar"}),
            shots=10,
            outputS3Bucket=bucket,
            outputS3KeyPrefix="results",
        )
    )
    assert err["Code"] == "ValidationException", f"malformed action: expected ValidationException, got {err!r}"
    expected = (
        "Provided action is not valid. Please refer to the github repo "
        "amazon-braket-schemas-python for examples"
    )
    assert err["Message"] == expected, f"malformed action: expected {expected!r}, got {err['Message']!r}"

    # Break #3: shots beyond the device's OWN reported shotsRange maximum (never a hardcoded
    # quota -- botocore's local shape has no upper bound on shots, so this one does reach AWS).
    err = _client_error(
        lambda: braket.create_quantum_task(
            clientToken=ctx.unique_name("sim2real-bad-shots-"),
            deviceArn=SV1_ARN,
            action=BELL_ACTION,
            shots=max_shots + 1,
            outputS3Bucket=bucket,
            outputS3KeyPrefix="results",
        )
    )
    assert err["Code"] == "ValidationException", f"shots beyond {max_shots}: expected ValidationException, got {err!r}"
    expected = (
        f"Shot count should be between {min_shots} and {max_shots} on {SV1_ARN}, "
        f"but found {max_shots + 1}."
    )
    assert err["Message"] == expected, f"shots beyond {max_shots}: expected {expected!r}, got {err['Message']!r}"

    # Positive control: same shape of request, nothing broken -- must succeed.
    resp = braket.create_quantum_task(
        clientToken=ctx.unique_name("sim2real-good-"),
        deviceArn=SV1_ARN,
        action=BELL_ACTION,
        shots=10,
        outputS3Bucket=bucket,
        outputS3KeyPrefix="results",
    )
    task_arn = resp["quantumTaskArn"]
    assert task_arn
    ctx.on_cleanup(lambda: _best_effort_cancel(ctx, braket, task_arn))


def _ensure_braket_service_linked_role(ctx) -> None:
    """CreateQuantumTask needs AWSServiceRoleForAmazonBraket to write results to S3; a fresh
    account doesn't have it yet. Create-or-adopt: it's a shared, idempotent, account-level
    resource, so it is NOT torn down."""
    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="braket.amazonaws.com")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidInput":
            raise


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _client_error_past_slr_propagation(fn, *, timeout_s=90.0):
    """A service-linked role created moments ago takes a while to become visible to Braket,
    which answers AccessDeniedException until then; retry only that refusal, bounded."""
    deadline = time.monotonic() + timeout_s
    while True:
        err = _client_error(fn)
        if err["Code"] != "AccessDeniedException" or "AWSServiceRoleForAmazonBraket" not in err["Message"]:
            return err
        if time.monotonic() >= deadline:
            raise AssertionError(f"service-linked role never became visible to Braket: {err!r}")
        time.sleep(3)


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
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "create-quantum-task-invalid-input-rejected"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})
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
