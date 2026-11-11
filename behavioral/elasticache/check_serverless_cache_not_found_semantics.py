"""serverless-cache-not-found-semantics."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _fault_base(code):
    """Strip the modeled Fault/Exception suffix so error codes compare on their base."""
    for suffix in ("Exception", "Fault"):
        if code and code.endswith(suffix) and len(code) > len(suffix):
            return code[: -len(suffix)]
    return code

def _error(fn):
    """Call fn(), which must raise a ClientError; return its (Error.Code, Error.Message)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected a ClientError but the call SUCCEEDED")

def _assert_error(fn, expected):
    """Assert fn() fails with `expected` (Fault/Exception-suffix normalized); return the message."""
    code, actual = _error(fn)
    assert _fault_base(code) == _fault_base(expected), f"expected {expected}, got {code} ({actual!r})"
    return actual

CHECK = "serverless-cache-not-found-semantics"
GROUP = 'serverless'
SERVICES = ['elasticache']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Serverless-cache reads/mutations for an unknown name raise ServerlessCacheNotFound."""
    ec = ctx.client("elasticache")
    bogus = ctx.unique_name("sim2real-behav-esc-missing-")
    not_found = f"Serverless cache with name {bogus} not found."
    message = _assert_error(
        lambda: ec.describe_serverless_caches(ServerlessCacheName=bogus),
        "ServerlessCacheNotFoundFault",
    )
    assert message == not_found, message
    message = _assert_error(
        lambda: ec.delete_serverless_cache(ServerlessCacheName=bogus),
        "ServerlessCacheNotFoundFault",
    )
    assert message == not_found, message
    message = _assert_error(
        lambda: ec.modify_serverless_cache(
            ServerlessCacheName=bogus, Description="nope",
        ),
        "ServerlessCacheNotFoundFault",
    )
    assert message == not_found, message
    message = _assert_error(
        lambda: ec.create_serverless_cache_snapshot(
            ServerlessCacheSnapshotName=ctx.unique_name("sim2real-behav-escs-"),
            ServerlessCacheName=bogus,
        ),
        "ServerlessCacheNotFoundFault",
    )
    assert message == not_found, message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
