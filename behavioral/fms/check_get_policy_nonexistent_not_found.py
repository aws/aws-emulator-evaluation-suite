"""get-policy-nonexistent-not-found."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "get-policy-nonexistent-not-found"
GROUP = "not-found"
SERVICES = ["fms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetPolicy on a PolicyId that meets the length and pattern but is not a UUID, and on a nonexistent UUID,
    fails with ResourceNotFoundException "The referenced item does not exist.", with no admin gate."""
    fms = ctx.client("fms")

    # 36 characters (matches PolicyId's fixed min/max length and pattern) but not a
    # UUID -- passed straight through as an opaque lookup key that simply doesn't exist.
    non_uuid_code, non_uuid_message = _client_error(lambda: fms.get_policy(PolicyId="x" * 36))
    assert non_uuid_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a well-formed-length non-UUID id, got {non_uuid_code}"
    )
    assert non_uuid_message == "The referenced item does not exist.", f"unexpected ResourceNotFoundException message: {non_uuid_message!r}"

    fake_policy_id = str(uuid.uuid4())
    code, message = _client_error(lambda: fms.get_policy(PolicyId=fake_policy_id))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for well-formed missing id, got {code}"
    )
    assert message == "The referenced item does not exist.", f"unexpected ResourceNotFoundException message: {message!r}"


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
