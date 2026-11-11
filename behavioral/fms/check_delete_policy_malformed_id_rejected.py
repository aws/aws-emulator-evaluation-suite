"""delete-policy-malformed-id-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-policy-malformed-id-rejected"
GROUP = "validation"
SERVICES = ["fms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeletePolicy on a 36-character non-UUID PolicyId and on a nonexistent UUID, and GetPolicy on the non-UUID,
    all fail with ResourceNotFoundException "The referenced item does not exist.": the id is an opaque key."""
    fms = ctx.client("fms")

    # 36 characters (matches PolicyId's minimum/maximum length) but not a UUID --
    # passed straight through as an opaque lookup key that simply doesn't exist.
    non_uuid_code, non_uuid_message = _client_error(lambda: fms.delete_policy(PolicyId="x" * 36))
    assert non_uuid_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a well-formed-length non-UUID id, got {non_uuid_code}"
    )
    assert non_uuid_message == "The referenced item does not exist.", f"unexpected ResourceNotFoundException message: {non_uuid_message!r}"

    import uuid

    wellformed_but_missing = str(uuid.uuid4())
    notfound_code, notfound_message = _client_error(lambda: fms.delete_policy(PolicyId=wellformed_but_missing))
    assert notfound_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for well-formed missing id, got {notfound_code}"
    )
    assert notfound_message == "The referenced item does not exist.", f"unexpected ResourceNotFoundException message: {notfound_message!r}"

    # Independent read at a different operation: GetPolicy must agree the same id is missing.
    get_code, get_message = _client_error(lambda: fms.get_policy(PolicyId=wellformed_but_missing))
    assert get_code == "ResourceNotFoundException", (
        f"expected GetPolicy to agree the same id is missing, got {get_code}"
    )
    assert get_message == "The referenced item does not exist.", f"unexpected ResourceNotFoundException message: {get_message!r}"


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
