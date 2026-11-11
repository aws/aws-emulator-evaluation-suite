"""describe-client-authentication-settings-nonexistent-directory."""

from __future__ import annotations

import uuid

from botocore.exceptions import ClientError


from behavioral_harness import tags


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message, RequestId) of the ClientError it
    raises. A success raises, so an emulator accepting what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        request_id = exc.response.get("ResponseMetadata", {}).get("RequestId")
        return err.get("Code"), err.get("Message"), request_id
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _require_op(ds, op_name):
    """Skip if this boto3 version lacks the operation (newer ds APIs are absent in
    older botocore)."""
    if not hasattr(ds, op_name):
        raise AssertionError(f"ds operation not available in this boto3: {op_name}")


CHECK = "describe-client-authentication-settings-nonexistent-directory"
GROUP = 'error-semantics'
SERVICES = ['ds']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeClientAuthenticationSettings fails with DirectoryDoesNotExistException and "Directory: '<id>'
    does not exist." for a well-formed absent id, and with ValidationException and the pattern message
    for a malformed one, so one code does not answer every bad input."""
    ds = ctx.client("ds")
    _require_op(ds, "describe_client_authentication_settings")

    # Control: the account-scoped read is a legitimate success, so the client, region
    # and credentials are otherwise healthy — a target that denies everything cannot
    # score a pass by coincidence.
    inventory = ds.describe_directories()
    assert isinstance(inventory.get("DirectoryDescriptions"), list), (
        f"unfiltered DescribeDirectories must return a DirectoryDescriptions list "
        f"before we test the absent-id path, got {inventory}"
    )

    absent = "d-" + uuid.uuid4().hex[:10]
    code, message, rid = _error(
        lambda: ds.describe_client_authentication_settings(
            DirectoryId=absent, Type="SmartCard"
        )
    )
    assert code == "DirectoryDoesNotExistException", (
        f"DescribeClientAuthenticationSettings(DirectoryId={absent}) — a well-formed "
        f"but never-created id — must raise DirectoryDoesNotExistException, got {code}"
    )
    expected_message = f"Directory: '{absent}' does not exist. : RequestId: {rid}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Distinguish "absent directory" from "always throws for this op": a DirectoryId
    # that fails the modeled pattern (^d-[0-9a-f]{10}$) is a malformed-input rejection
    # at the request-validation layer, ValidationException — not the not-found code
    # above. A stub that hard-codes DirectoryDoesNotExistException for every call to
    # this operation fails this leg.
    malformed_code, malformed_message, malformed_rid = _error(
        lambda: ds.describe_client_authentication_settings(
            DirectoryId="not-a-directory-id", Type="SmartCard"
        )
    )
    assert malformed_code == "ValidationException", (
        f"DescribeClientAuthenticationSettings(DirectoryId='not-a-directory-id') — a "
        f"malformed id — must raise ValidationException, got {malformed_code}"
    )
    expected_malformed = (
        "1 validation error detected: Value 'not-a-directory-id' at 'directoryId' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: ^d-[0-9a-f]{10}$"
    )
    assert malformed_message == expected_malformed, (
        f"expected message {expected_malformed!r}, got {malformed_message!r}"
    )
    assert malformed_code != code, (
        f"a malformed DirectoryId and an absent-but-well-formed DirectoryId must not "
        f"share one error code ({code!r}) — the target is funnelling every bad input "
        f"into a single response"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
