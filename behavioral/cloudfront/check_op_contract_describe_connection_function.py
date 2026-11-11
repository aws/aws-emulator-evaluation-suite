"""op-contract-describeConnectionFunction."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-describeConnectionFunction"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeConnectionFunction: describes a freshly created connection
    function (status/stage present), and rejects an unknown identifier
    (EntityNotFound)."""
    cf = ctx.client("cloudfront")
    if not (hasattr(cf, "create_connection_function") and hasattr(cf, "describe_connection_function")):
        raise AssertionError(
            "unreachable: {create,describe}_connection_function not present in installed botocore"
        )

    name = ctx.unique_name("sim2real-connfn-")
    code_body = b"function handler(event) { return event; }"
    try:
        created = cf.create_connection_function(
            Name=name,
            ConnectionFunctionConfig={
                "Comment": "sim2real behavioral check",
                "Runtime": "cloudfront-js-2.0",
            },
            ConnectionFunctionCode=code_body,
        )
    except Exception as exc:  # pragma: no cover - environment dependent
        raise AssertionError(f"CreateConnectionFunction unavailable in this account/region: {exc}")

    fn_id = created["ConnectionFunctionSummary"]["Id"]
    etag = created["ETag"]
    ctx.on_cleanup(lambda: _safe_delete(cf, fn_id))

    described = cf.describe_connection_function(Identifier=fn_id)
    summary = described["ConnectionFunctionSummary"]
    assert summary["Id"] == fn_id, f"expected Id {fn_id}, got {summary['Id']}"
    assert summary["Stage"] == "DEVELOPMENT", f"expected DEVELOPMENT, got {summary['Stage']}"

    # distinct error boundary: unknown identifier (well-formed but nonexistent:
    # mutate the last character rather than appending, since a garbled Id can
    # surface a format-validation error instead of EntityNotFound)
    bogus_id = fn_id[:-1] + ("0" if fn_id[-1] != "0" else "1")
    code, msg = _error(lambda: cf.describe_connection_function(Identifier=bogus_id))
    assert code == "EntityNotFound", f"expected EntityNotFound, got {code}"
    assert msg == "The specified connection function does not exist.", f"unexpected EntityNotFound message: {msg!r}"

    cf.delete_connection_function(Id=fn_id, IfMatch=etag)
    gone_code, gone_msg = _error(lambda: cf.describe_connection_function(Identifier=fn_id))
    assert gone_code == "EntityNotFound", f"expected EntityNotFound after delete, got {gone_code}"
    assert gone_msg == "The specified connection function does not exist.", f"unexpected EntityNotFound message after delete: {gone_msg!r}"


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that
    succeeds raises AssertionError: an emulator accepting input real AWS refuses must fail
    loudly, not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _safe_delete(cf, fn_id: str) -> None:
    try:
        current = cf.describe_connection_function(Identifier=fn_id)
        cf.delete_connection_function(Id=fn_id, IfMatch=current["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
