"""create-alias-invalid-alias-rejected."""

from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


_ALIAS_PATTERN = r"^(?!D-|d-)([\da-zA-Z]+)([-]*[\da-zA-Z])*"


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message, RequestId). Raises if the call succeeded."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        request_id = (exc.response.get("ResponseMetadata") or {}).get("RequestId")
        return err.get("Code"), err.get("Message"), request_id
    raise AssertionError(f"expected a ClientError, call succeeded with {resp!r}")


CHECK = "create-alias-invalid-alias-rejected"
GROUP = 'error-semantics'
SERVICES = ['ds']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAlias validates the alias before the directory lookup: a malformed alias against a nonexistent
    directory fails with ValidationException and the pattern message, while a well-formed alias against
    the same id fails with EntityDoesNotExistException and "Directory: '<id>' does not exist."."""
    ds = ctx.client("ds")
    directory_id = "d-" + uuid.uuid4().hex[:10]

    bad_alias = "SIM2REAL_Invalid_Alias"
    bad_code, bad_message, _ = _error(
        lambda: ds.create_alias(DirectoryId=directory_id, Alias=bad_alias)
    )
    assert bad_code == "ValidationException", f"expected ValidationException, got {bad_code!r}"
    assert bad_message == (
        f"1 validation error detected: Value '{bad_alias}' at 'alias' failed to satisfy "
        f"constraint: Member must satisfy regular expression pattern: {_ALIAS_PATTERN}"
    ), f"unexpected ValidationException message: {bad_message!r}"

    good_alias = "sim2real-" + uuid.uuid4().hex[:10]
    good_code, good_message, good_request_id = _error(
        lambda: ds.create_alias(DirectoryId=directory_id, Alias=good_alias)
    )
    assert good_code == "EntityDoesNotExistException", (
        f"expected EntityDoesNotExistException for a well-formed alias against a "
        f"nonexistent directory, got {good_code!r}"
    )
    assert good_message == (
        f"Directory: '{directory_id}' does not exist. : RequestId: {good_request_id}"
    ), f"unexpected EntityDoesNotExistException message: {good_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
