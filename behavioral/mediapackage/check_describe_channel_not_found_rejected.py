"""describe-channel-not-found-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-channel-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediapackage"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeChannel on an Id that was never created is rejected with NotFoundException;
    a real Channel with the same naming shape is still describable (positive control), and
    once that Channel is deleted the identical DescribeChannel call fails the same way."""
    mp = ctx.client("mediapackage")

    bogus_id = ctx.unique_name("sim2real-mp-ch-missing-")
    code, message = _error_code(lambda: mp.describe_channel(Id=bogus_id))
    assert code == "NotFoundException", (
        f"expected NotFoundException for a never-created channel Id, got {code!r}"
    )
    expected_message = f"channel with id={bogus_id} not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    real_id = ctx.unique_name("sim2real-mp-ch-")
    mp.create_channel(Id=real_id, Tags={"created-by": "sim2real"})
    ctx.on_cleanup(lambda: _swallow(lambda: mp.delete_channel(Id=real_id)))
    described = mp.describe_channel(Id=real_id)
    assert described["Id"] == real_id, (
        f"expected DescribeChannel to return Id={real_id!r}, got {described.get('Id')!r}"
    )

    mp.delete_channel(Id=real_id)
    code_after_delete, message_after_delete = _error_code(lambda: mp.describe_channel(Id=real_id))
    assert code_after_delete == "NotFoundException", (
        f"expected NotFoundException after deleting {real_id!r}, got {code_after_delete!r}"
    )
    expected_after = f"channel with id={real_id} not found"
    assert message_after_delete == expected_after, (
        f"expected message {expected_after!r}, got {message_after_delete!r}"
    )


def _error_code(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
