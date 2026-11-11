"""get-resolver-endpoint-invalid-id-format-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-resolver-endpoint-invalid-id-format-rejected"
GROUP = "error-semantics"
SERVICES = ["route53resolver"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetResolverEndpoint with an id over 64 characters is refused with ValidationException, while
    never-created ids within the limit, whatever their prefix, are refused with
    ResourceNotFoundException ("[RSLVR-00501] Resolver endpoint with ID ... does not exist.").
    """
    client = ctx.client("route53resolver")

    oversized_id = "rslvr-in-" + uuid.uuid4().hex + uuid.uuid4().hex  # far past the 64-char max
    oversized_code, oversized_message = _error(
        lambda: client.get_resolver_endpoint(ResolverEndpointId=oversized_id)
    )
    assert oversized_code == "ValidationException", (
        f"got={oversized_code!r} expected=ValidationException for an oversized "
        f"(len={len(oversized_id)}) id -- must not be treated as a plain lookup miss"
    )
    expected = (
        f"1 validation error detected: Value '{oversized_id}' at 'resolverEndpointId' failed to "
        "satisfy constraint: Member must have length less than or equal to 64"
    )
    assert oversized_message == expected, f"expected message {expected!r}, got {oversized_message!r}"

    well_formed_missing_code, well_formed_missing_message = _error(
        lambda: client.get_resolver_endpoint(ResolverEndpointId="rslvr-in-0123456789abcdef0")
    )
    assert well_formed_missing_code == "ResourceNotFoundException", (
        f"got={well_formed_missing_code!r} expected=ResourceNotFoundException for missing id"
    )
    expected = '[RSLVR-00501] Resolver endpoint with ID "rslvr-in-0123456789abcdef0" does not exist.'
    assert well_formed_missing_message == expected, (
        f"expected message {expected!r}, got {well_formed_missing_message!r}"
    )

    # A non-"rslvr-" prefixed but length-valid id is still just a lookup miss: Route 53
    # Resolver does not validate endpoint-id *prefix* shape server-side, only existence.
    differently_shaped_code, differently_shaped_message = _error(
        lambda: client.get_resolver_endpoint(ResolverEndpointId="not-a-valid-resolver-endpoint-id")
    )
    assert differently_shaped_code == "ResourceNotFoundException", (
        f"got={differently_shaped_code!r} expected=ResourceNotFoundException for a length-valid, "
        f"non-rslvr-prefixed id"
    )
    expected = '[RSLVR-00501] Resolver endpoint with ID "not-a-valid-resolver-endpoint-id" does not exist.'
    assert differently_shaped_message == expected, (
        f"expected message {expected!r}, got {differently_shaped_message!r}"
    )


_TRACE_ID = ' Trace Id: "'


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises, with the
    per-request X-Ray trace id suffix removed. A call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        message = err.get("Message", "")
        head, sep, _ = message.rpartition(_TRACE_ID)
        return err.get("Code"), (head if sep and message.endswith('"') else message)
    raise AssertionError(f"expected a ClientError, the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
