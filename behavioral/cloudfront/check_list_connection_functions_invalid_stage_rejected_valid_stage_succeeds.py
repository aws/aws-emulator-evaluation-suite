"""list-connection-functions-invalid-stage-rejected-valid-stage-succeeds."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-connection-functions-invalid-stage-rejected-valid-stage-succeeds"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListConnectionFunctions rejects an out-of-enum Stage filter with MalformedXML instead
    of silently ignoring it, while LIVE, DEVELOPMENT and no Stage filter all succeed (positive
    control on the same operation)."""
    cf = ctx.client("cloudfront")

    # Break exactly one thing: an out-of-enum Stage value. Empirically,
    # CloudFront's request-XML deserializer rejects this before it ever
    # reaches business logic, surfacing as MalformedXML (an enum value that
    # isn't one of the wire enum's known members fails to parse) -- a
    # distinct, deterministic rejection from a bare 200/empty-list no-op.
    exc = _capture_client_error(lambda: cf.list_connection_functions(Stage="NOT_A_REAL_STAGE"))
    assert exc is not None, "expected ListConnectionFunctions(Stage=<bogus>) to raise, but it returned a response"
    assert exc.response["Error"]["Code"] == "MalformedXML", exc.response["Error"]["Code"]
    assert exc.response["Error"]["Message"] == "1 validation error detected: Value 'NOT_A_REAL_STAGE' at 'stage' failed to satisfy constraint: Member must satisfy enum value set: [LIVE, DEVELOPMENT]", (
        f'expected the exact MalformedXML message AWS returns, got {exc.response["Error"]["Message"]!r}'
    )

    # Positive control: valid Stage values, and no Stage filter at all, both
    # succeed normally on the same operation.
    for kwargs in ({"Stage": "LIVE"}, {"Stage": "DEVELOPMENT"}, {}):
        resp = cf.list_connection_functions(**kwargs)
        assert "ConnectionFunctions" in resp, f"ListConnectionFunctions({kwargs}) response missing ConnectionFunctions: {resp!r}"
        assert isinstance(resp["ConnectionFunctions"], list), (
            f"ListConnectionFunctions({kwargs}) ConnectionFunctions should be a list, "
            f"got {type(resp['ConnectionFunctions'])!r}"
        )


def _capture_client_error(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

