"""op-generate-random-oversized-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-generate-random-oversized-rejected"
GROUP = 'random'
SERVICES = ['kms']


def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GenerateRandom accepts exactly 1024 bytes and must reject 1025."""
    kms = ctx.client("kms")
    at_limit = kms.generate_random(NumberOfBytes=1024)
    got = len(at_limit["Plaintext"])
    assert got == 1024, f"expected 1024 bytes at the documented cap, got {got}"

    for n in (1025, 2048):  # 2048 is well past the cap and must also be a server-side rejection
        code, message = _error(lambda n=n: kms.generate_random(NumberOfBytes=n))
        assert code == "ValidationException", f"{n} -> expected ValidationException, got {code}"
        assert message == (
            f"1 validation error detected: Value '{n}' at 'numberOfBytes' failed to satisfy "
            "constraint: Member must have value less than or equal to 1024"
        ), message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
