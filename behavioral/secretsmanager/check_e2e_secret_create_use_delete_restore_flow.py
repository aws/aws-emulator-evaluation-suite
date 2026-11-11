"""e2e-secret-create-use-delete-restore-flow."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-secret-create-use-delete-restore-flow"
GROUP = "state-machine"
SERVICES = ["secretsmanager"]

_MARKED_FOR_DELETION = (
    "You can't perform this operation on the secret because it was marked for deletion."
)


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "concern:negative-classes",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Create, write, read, schedule-delete, restore: the secret is unusable while pending
    deletion and fully usable again — with original data intact — once restored."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secmgr-restoreflow-")

    created = sm.create_secret(Name=name, SecretString="original-value-v1")
    secret_arn = created["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    value = sm.get_secret_value(SecretId=secret_arn)["SecretString"]
    assert value == "original-value-v1", f"expected seed value right after create, got {value!r}"

    sm.delete_secret(SecretId=secret_arn)
    deleted_desc = sm.describe_secret(SecretId=secret_arn)
    assert "DeletedDate" in deleted_desc, f"expected DeletedDate after schedule-delete, got keys {sorted(deleted_desc)}"

    # A secret scheduled for deletion is not just tombstoned metadata: reads and writes of
    # its value must be rejected while pending, or a target that never enforces the deleted
    # state at all would pass every other assertion in this file unnoticed.
    read_err = _error(lambda: sm.get_secret_value(SecretId=secret_arn))
    assert read_err.get("Code") == "InvalidRequestException", f"expected GetSecretValue rejected while pending deletion, got {read_err}"
    assert read_err.get("Message") == _MARKED_FOR_DELETION, f"unexpected GetSecretValue message: {read_err.get('Message')!r}"
    write_err = _error(lambda: sm.put_secret_value(SecretId=secret_arn, SecretString="sneaky-while-deleted"))
    assert write_err.get("Code") == "InvalidRequestException", f"expected PutSecretValue rejected while pending deletion, got {write_err}"
    assert write_err.get("Message") == _MARKED_FOR_DELETION, f"unexpected PutSecretValue message: {write_err.get('Message')!r}"

    sm.restore_secret(SecretId=secret_arn)
    restored_desc = sm.describe_secret(SecretId=secret_arn)
    assert "DeletedDate" not in restored_desc, f"expected DeletedDate cleared after restore, got {restored_desc.get('DeletedDate')!r}"

    # Original data must have survived the delete/restore cycle unchanged.
    value = sm.get_secret_value(SecretId=secret_arn)["SecretString"]
    assert value == "original-value-v1", f"expected original value to survive delete/restore, got {value!r}"

    # The secret must be fully usable again: a fresh write must succeed and become current.
    # PutSecretValue/GetSecretValue right after a restore can briefly lag on propagation, so
    # poll to a bounded deadline rather than asserting on a single immediate read.
    sm.put_secret_value(SecretId=secret_arn, SecretString="post-restore-value-v2")
    final_value = _poll_for_value(sm, secret_arn, "post-restore-value-v2", timeout_s=30.0)
    assert final_value == "post-restore-value-v2", f"expected post-restore write to become current within 30s, got {final_value!r}"


def _error(fn):
    """Call fn(); return the botocore Error dict. An unexpected SUCCESS raises, so a target
    accepting what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_for_value(sm, secret_arn: str, expected: str, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    last_value = sm.get_secret_value(SecretId=secret_arn)["SecretString"]
    while last_value != expected:
        if time.monotonic() >= deadline:
            raise AssertionError(f"post-restore value never became {expected!r} within {timeout_s}s, last saw {last_value!r}")
        time.sleep(2)
        last_value = sm.get_secret_value(SecretId=secret_arn)["SecretString"]
    return last_value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
