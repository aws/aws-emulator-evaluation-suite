"""braket-resource-not-found-error-semantics-consistent."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "braket-resource-not-found-error-semantics-consistent"
GROUP = "error-semantics"
SERVICES = ["braket"]


def _error_code(fn):
    """(code, message) of the ClientError fn raises; an unexpected success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Read/mutate operations on a well-formed but nonexistent ARN report ResourceNotFoundException,
    except ListTagsForResource, which reports NotFoundException."""
    braket = ctx.client("braket")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region
    ghost = ctx.unique_name("sim2real-ghost-")
    # Quantum-task identifiers are validated as UUIDs before an existence lookup is even
    # attempted, so a non-UUID suffix is rejected with ValidationException rather than
    # ResourceNotFoundException. Use a syntactically valid (but never-issued) UUID instead.
    ghost_task_id = str(uuid.uuid4())

    fake_device = "arn:aws:braket:::device/quantum-simulator/sim2real/ghost-device-does-not-exist"
    fake_job = f"arn:aws:braket:{region}:{account_id}:job/{ghost}"
    fake_task = f"arn:aws:braket:{region}:{account_id}:quantum-task/{ghost_task_id}"
    fake_spending_limit = f"arn:aws:braket:{region}:{account_id}:spending-limit/{ghost}"

    _get_device_code, _get_device_message = _error_code(lambda: braket.get_device(deviceArn=fake_device))
    assert _get_device_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {_get_device_code!r}"
    )
    assert _get_device_message == f"Braket device '{fake_device}' not found in {ctx.region}. You can find a list of all supported device ARNs and the regions in which they are available in the documentation: https://docs.aws.amazon.com/braket/latest/developerguide/braket-devices.html", (
        f"expected the exact ResourceNotFoundException message AWS returns, got {_get_device_message!r}"
    )
    _get_job_code, _get_job_message = _error_code(lambda: braket.get_job(jobArn=fake_job))
    assert _get_job_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {_get_job_code!r}"
    )
    assert _get_job_message == f"Job {ctx.account}#{ghost} not found", (
        f"expected the exact ResourceNotFoundException message AWS returns, got {_get_job_message!r}"
    )
    _quantum_task_code, _quantum_task_message = _error_code(lambda: braket.get_quantum_task(quantumTaskArn=fake_task))
    assert _quantum_task_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {_quantum_task_code!r}"
    )
    assert _quantum_task_message == "Quantum task not found", (
        f"expected the exact ResourceNotFoundException message AWS returns, got {_quantum_task_message!r}"
    )
    # ListTagsForResource uses its own NotFoundException shape rather than the
    # ResourceNotFoundException used by the other read/mutate operations (empirically
    # verified against the live Braket control plane).
    _list_tags_code, _list_tags_message = _error_code(lambda: braket.list_tags_for_resource(resourceArn=fake_task))
    assert _list_tags_code == "NotFoundException", (
        f"expected NotFoundException, got {_list_tags_code!r}"
    )
    assert _list_tags_message == "Resource was not found", (
        f"expected the exact NotFoundException message AWS returns, got {_list_tags_message!r}"
    )
    _delete_limit_code, _delete_limit_message = _error_code(
        lambda: braket.delete_spending_limit(spendingLimitArn=fake_spending_limit)
    )
    assert _delete_limit_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {_delete_limit_code!r}"
    )
    assert _delete_limit_message == f"Spending limit {fake_spending_limit} not found", (
        f"expected the exact ResourceNotFoundException message AWS returns, got {_delete_limit_message!r}"
    )
    _cancel_job_code, _cancel_job_message = _error_code(lambda: braket.cancel_job(jobArn=fake_job))
    assert _cancel_job_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {_cancel_job_code!r}"
    )
    assert _cancel_job_message == f"Job {ctx.account}#{ghost} not found", (
        f"expected the exact ResourceNotFoundException message AWS returns, got {_cancel_job_message!r}"
    )
    _cancel_task_code, _cancel_task_message = _error_code(
        lambda: braket.cancel_quantum_task(
            quantumTaskArn=fake_task, clientToken=ctx.unique_name("sim2real-cancel-")
        )
    )
    assert _cancel_task_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {_cancel_task_code!r}"
    )
    assert _cancel_task_message == "Quantum task not found", (
        f"expected the exact ResourceNotFoundException message AWS returns, got {_cancel_task_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
