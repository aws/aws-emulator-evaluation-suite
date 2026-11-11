"""access-request-start-then-get-token-lifecycle."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "access-request-start-then-get-token-lifecycle"
GROUP = "state-machine"
SERVICES = ["ssm"]

_JIT_DISABLED = "Just-In-Time Node Access service is not enabled in this account."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """On an account without just-in-time node access enabled, StartAccessRequest and GetAccessToken
    both reject with ValidationException and the JIT-disabled message before any target or request
    lookup, while a DescribeInstanceInformation positive control succeeds.
    """

    ssm = ctx.client("ssm")

    ssm.describe_instance_information(MaxResults=5)

    start_code, start_message = _error_code(
        lambda: ssm.start_access_request(
            Reason="access-request-probe",
            Targets=[{"Key": "InstanceIds", "Values": ["i-00000000000000000"]}],
        )
    )
    assert start_code == "ValidationException", (
        f"expected ValidationException for StartAccessRequest on an account with "
        f"just-in-time node access never enabled, got {start_code}"
    )
    assert start_message == _JIT_DISABLED, (
        f"expected message {_JIT_DISABLED!r}, got {start_message!r}"
    )

    fake_access_request_id = "oi-" + uuid.uuid4().hex[:12]
    token_code, token_message = _error_code(lambda: ssm.get_access_token(AccessRequestId=fake_access_request_id))
    assert token_code == "ValidationException", (
        f"expected ValidationException for GetAccessToken on an account with "
        f"just-in-time node access never enabled, got {token_code}"
    )
    assert token_message == _JIT_DISABLED, (
        f"expected message {_JIT_DISABLED!r}, got {token_message!r}"
    )


# ===== helpers =====
def _error_code(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because an
    over-permissive target accepting input real AWS refuses must not be reported as an
    error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

