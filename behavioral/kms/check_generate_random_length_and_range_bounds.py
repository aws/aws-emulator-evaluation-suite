"""generate-random-length-and-range-bounds."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "generate-random-length-and-range-bounds"
GROUP = "random"
SERVICES = ["kms"]

_BELOW_MINIMUM = (
    "ValidationException",
    "1 validation error detected: Value '0' at 'numberOfBytes' failed to satisfy constraint: "
    "Member must have value greater than or equal to 1",
)
_ABOVE_MAXIMUM = (
    "ValidationException",
    "1 validation error detected: Value '1025' at 'numberOfBytes' failed to satisfy constraint: "
    "Member must have value less than or equal to 1024",
)


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GenerateRandom returns exactly the requested byte count at 1, 32 and 1024 bytes, two
    32-byte draws differ, and 0 and 1025 are each refused with the bound's exact message.
    """
    kms = ctx.client("kms")
    # botocore validates NumberOfBytes' lower bound locally, which would never reach the
    # service's own refusal; route the below-minimum call through a client that does not.
    kms_unvalidated = ctx.client("kms", config=Config(parameter_validation=False))

    smallest = kms.generate_random(NumberOfBytes=1)["Plaintext"]
    assert len(smallest) == 1, f"expected 1 byte, got {len(smallest)}"

    draw1 = kms.generate_random(NumberOfBytes=32)["Plaintext"]
    assert len(draw1) == 32, f"expected 32 bytes, got {len(draw1)}"
    draw2 = kms.generate_random(NumberOfBytes=32)["Plaintext"]
    assert len(draw2) == 32, f"expected 32 bytes, got {len(draw2)}"
    assert draw1 != draw2, f"two independent 32-byte draws were identical: {draw1!r}"

    largest = kms.generate_random(NumberOfBytes=1024)["Plaintext"]
    assert len(largest) == 1024, f"expected 1024 bytes, got {len(largest)}"

    expect_error(lambda: kms_unvalidated.generate_random(NumberOfBytes=0), *_BELOW_MINIMUM)
    expect_error(lambda: kms.generate_random(NumberOfBytes=1025), *_ABOVE_MAXIMUM)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
