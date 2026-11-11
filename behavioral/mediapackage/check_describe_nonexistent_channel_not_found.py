"""describe-nonexistent-channel-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-nonexistent-channel-not-found"
GROUP = "error-semantics"
SERVICES = ["mediapackage"]


def _error_code(fn):
    """Run fn; return the ClientError (code, message). Raises if fn unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeChannel on a never-created Id fails NotFoundException with the exact message; a real channel
    is describable, and after DeleteChannel it converges to the same NotFoundException message."""
    mp = ctx.client("mediapackage")

    bogus_id = ctx.unique_name("sim2real-mp-missing-")
    code, message = _error_code(lambda: mp.describe_channel(Id=bogus_id))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    expected_message = f"channel with id={bogus_id} not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    real_id = ctx.unique_name("sim2real-mp-real-")
    mp.create_channel(Id=real_id)
    deleted = {"v": False}

    def _cleanup():
        if not deleted["v"]:
            mp.delete_channel(Id=real_id)

    ctx.on_cleanup(_cleanup)

    described = mp.describe_channel(Id=real_id)
    assert described["Id"] == real_id, f"expected {real_id}, got {described.get('Id')}"

    mp.delete_channel(Id=real_id)
    deleted["v"] = True

    deadline = time.monotonic() + 60.0
    code_after_delete = message_after_delete = None
    while time.monotonic() < deadline:
        try:
            mp.describe_channel(Id=real_id)
        except ClientError as e:
            code_after_delete = e.response["Error"]["Code"]
            message_after_delete = e.response["Error"].get("Message")
            break
        time.sleep(3.0)
    assert code_after_delete == "NotFoundException", (
        f"expected NotFoundException after delete, got {code_after_delete}"
    )
    expected_after = f"channel with id={real_id} not found"
    assert message_after_delete == expected_after, (
        f"expected message {expected_after!r}, got {message_after_delete!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
