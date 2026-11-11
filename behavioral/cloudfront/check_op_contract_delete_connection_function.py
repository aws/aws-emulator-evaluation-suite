"""op-contract-deleteConnectionFunction."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteConnectionFunction"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

_CODE = b"function handler(event) {\n    return { decision: 'allow' };\n}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteConnectionFunction: deleting a nonexistent Id is rejected distinctly,
    and deleting a real one removes it so Describe reports NotFound."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-connfn-")[:64]

    try:
        created = cf.create_connection_function(
            Name=name,
            ConnectionFunctionConfig={
                "Comment": "sim2real behavioral check",
                "Runtime": "cloudfront-js-2.0",
            },
            ConnectionFunctionCode=_CODE,
            Tags={"Items": [{"Key": "sim2real-check", "Value": "true"}]},
        )
    except ClientError as exc:
        raise AssertionError(
            f"unreachable: CreateConnectionFunction unavailable/rejected in this account: "
            f"{exc.response['Error']['Code']}"
        ) from exc

    fn_id = created["ConnectionFunctionSummary"]["Id"]
    etag = created["ETag"]

    def _cleanup(fn_id=fn_id):
        try:
            fresh = cf.describe_connection_function(Identifier=fn_id)
            cf.delete_connection_function(Id=fn_id, IfMatch=fresh["ETag"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "EntityNotFound":
                raise

    ctx.on_cleanup(_cleanup)

    # error boundary: deleting a nonexistent connection function. A well-formed
    # (but non-matching) IfMatch value is required here: CloudFront validates the
    # IfMatch format/version before checking whether the Id exists, so a garbled
    # value like '"bogus"' surfaces InvalidIfMatchVersion instead of EntityNotFound.
    # Reusing a real, correctly-formatted ETag isolates the existence check.
    #
    # Similarly, the Id itself must be well-formed: CloudFront validates the Id
    # format before checking existence, so an arbitrary string like
    # "sim2real-nonexistent-cf-id" surfaces InvalidArg instead of EntityNotFound.
    # Derive a syntactically valid but nonexistent Id by mutating the last
    # character of the real (correctly-formatted) Id.
    bogus_fn_id = fn_id[:-1] + ("0" if fn_id[-1] != "0" else "1")
    nf_code, nf_message = _error(
        lambda: cf.delete_connection_function(
            Id=bogus_fn_id, IfMatch=etag
        )
    )
    assert nf_code == "EntityNotFound", f"expected EntityNotFound, got {nf_code}"
    assert nf_message == "The specified connection function does not exist.", (
        f"expected the exact refusal message, got {nf_message!r}"
    )

    # success path
    cf.delete_connection_function(Id=fn_id, IfMatch=etag)
    gone_code, gone_message = _error(lambda: cf.describe_connection_function(Identifier=fn_id))
    assert gone_code == "EntityNotFound", f"expected EntityNotFound after delete, got {gone_code}"
    assert gone_message == "The specified connection function does not exist.", (
        f"expected the exact refusal message, got {gone_message!r}"
    )

    # a mutation on the now-dead id must also fail (not just a synthesized nonexistent one):
    # re-deleting the same fn_id proves the delete was not silently a no-op accepted twice.
    redelete_code, redelete_message = _error(lambda: cf.delete_connection_function(Id=fn_id, IfMatch=etag))
    assert redelete_code == "EntityNotFound", f"expected EntityNotFound on re-delete, got {redelete_code}"
    assert redelete_message == "The specified connection function does not exist.", (
        f"expected the exact refusal message, got {redelete_message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises,
    because an emulator accepting input real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
