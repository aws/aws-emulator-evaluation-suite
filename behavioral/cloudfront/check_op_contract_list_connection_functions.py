"""op-contract-listConnectionFunctions."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-listConnectionFunctions"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListConnectionFunctions returns a well-shaped list; an invalid Stage enum
    value fails the request's XML enum validation with MalformedXML."""
    cf = ctx.client("cloudfront")

    try:
        resp = cf.list_connection_functions()
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("UnsupportedOperation", "AccessDenied"):
            raise AssertionError(f"connection functions unavailable: {code}")
        raise

    assert "ConnectionFunctions" in resp, f"expected ConnectionFunctions in response, got keys {list(resp)}"
    assert isinstance(resp["ConnectionFunctions"], list), (
        f"expected ConnectionFunctions to be a list, got {type(resp['ConnectionFunctions'])!r}"
    )

    code, msg = _error(lambda: cf.list_connection_functions(Stage="NOT_A_REAL_STAGE"))
    assert code == "MalformedXML", f"expected MalformedXML, got {code}"
    assert msg == "1 validation error detected: Value 'NOT_A_REAL_STAGE' at 'stage' failed to satisfy constraint: Member must satisfy enum value set: [LIVE, DEVELOPMENT]", f"unexpected MalformedXML message: {msg!r}"


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that
    succeeds raises AssertionError: an emulator accepting input real AWS refuses must fail
    loudly, not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
