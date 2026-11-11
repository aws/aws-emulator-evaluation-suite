"""delete-memory-record-invalid-input-malformed-id."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-memory-record-invalid-input-malformed-id"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteMemoryRecord with a memoryRecordId that fails its `^mem-[a-zA-Z0-9-_]*$` pattern
    returns ValidationException, while a well-formed but nonexistent id on the same memory returns
    ResourceNotFoundException ('MemoryItem does not exist').
    """
    agentcore = ctx.client("bedrock-agentcore")
    memory_id = "sim2realmissingmem-abc1122334"

    # Must satisfy the client-side length check (40-50 chars) so the request actually
    # reaches the service, but violate the `mem-[a-zA-Z0-9-_]*` prefix pattern.
    malformed_record_id = "x" * 44
    well_formed_missing_record_id = "mem-" + ("sim2real" + "0123456789" * 5)[:44]
    assert 40 <= len(malformed_record_id) <= 50, (
        f"malformed_record_id length {len(malformed_record_id)} outside the 40-50 client-side bound"
    )
    assert 40 <= len(well_formed_missing_record_id) <= 50, (
        f"well_formed_missing_record_id length {len(well_formed_missing_record_id)} outside the "
        "40-50 client-side bound"
    )

    # Primary assertion: malformed memoryRecordId -> ValidationException (the pattern
    # violation is a URI-path shape-level check, reported as a generic validation error).
    code, message = _error(
        lambda: agentcore.delete_memory_record(memoryId=memory_id, memoryRecordId=malformed_record_id)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = (
        "1 validation error detected: Value at 'memoryRecordId' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: mem-[a-zA-Z0-9-_]*"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Contrast: a well-formed but nonexistent memoryRecordId reaches the existence check
    # instead, proving pattern-violation rejection happens before -- and distinctly from --
    # resource lookup, rather than the emulator blanket-returning the same error for every
    # DeleteMemoryRecord call.
    contrast_code, contrast_message = _error(
        lambda: agentcore.delete_memory_record(
            memoryId=memory_id, memoryRecordId=well_formed_missing_record_id
        )
    )
    assert contrast_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for well-formed missing id, got {contrast_code}"
    )
    assert contrast_message == "MemoryItem does not exist", (
        f"expected message 'MemoryItem does not exist', got {contrast_message!r}"
    )


def _error(fn):
    """The (code, message) of the ClientError fn raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
