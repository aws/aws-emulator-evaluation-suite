"""disassociate-kms-key-nonexistent-log-group-fails."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "disassociate-kms-key-nonexistent-log-group-fails"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisassociateKmsKey is accepted on an existing log group with no key, and on a missing group raises
    ResourceNotFoundException "The specified log group does not exist."."""
    logs = ctx.client("logs")

    real_log_group = ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(
        logGroupName=real_log_group, tags={"Sim2RealOwner": "behavioral-suite"}
    )
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=real_log_group))

    # Positive control: DisassociateKmsKey on a real, existing log group succeeds as a
    # no-op; a refusal raises here.
    logs.disassociate_kms_key(logGroupName=real_log_group)

    missing_log_group = ctx.unique_name("sim2real-behav-missing-lg-")

    code, message = _error(lambda: logs.disassociate_kms_key(logGroupName=missing_log_group))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for DisassociateKmsKey on a nonexistent "
        f"log group, got {code}"
    )
    assert message == "The specified log group does not exist.", (
        f"unexpected DisassociateKmsKey message for a nonexistent log group: {message!r}"
    )


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
