"""list-resolver-endpoints-invalid-next-token-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-resolver-endpoints-invalid-next-token-rejected"
GROUP = "error-semantics"
SERVICES = ["route53resolver"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListResolverEndpoints with a tampered/garbage NextToken is rejected with
    InvalidNextTokenException, while the same call without a NextToken still succeeds
    (positive control proving the API itself is healthy)."""
    client = ctx.client("route53resolver")

    code, message = _error(
        lambda: client.list_resolver_endpoints(NextToken="not-a-real-next-token-!!!")
    )
    assert code == "InvalidNextTokenException", f"expected InvalidNextTokenException, got {code!r}"
    expected = '[RSLVR-00302] Invalid next token: "not-a-real-next-token-!!!", invalid version.'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # positive control: the same operation without a bogus token still works, and honors
    # MaxResults -- a target that ignores pagination entirely would still pass a bare
    # "key present" check, so pin the bound it actually promised.
    result = client.list_resolver_endpoints(MaxResults=5)
    endpoints = result["ResolverEndpoints"]
    assert isinstance(endpoints, list) and len(endpoints) <= 5, (
        f"expected at most 5 resolver endpoints (MaxResults=5), got {len(endpoints)}"
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
