"""op-contract-get-connection-function."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-connection-function"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetConnectionFunction returns the uploaded code/content-type, and 404s on unknown Identifier."""
    cf = ctx.client("cloudfront")

    # distinct error boundary is cheap and has no prerequisites: run it unconditionally.
    not_found_message = "The specified connection function does not exist."
    code, message = _error(lambda: cf.get_connection_function(Identifier="sim2real-nonexistent-connfn"))
    assert code == "EntityNotFound", f"unexpected code {code}"
    assert message == not_found_message, f"expected message {not_found_message!r}, got {message!r}"

    name = ctx.unique_name("sim2real-connfn-").replace("-", "")[:64]
    fn_code = (
        b"async function handler(event) {\n"
        b"    return true;\n"
        b"}"
    )
    try:
        created = cf.create_connection_function(
            Name=name,
            ConnectionFunctionConfig={"Comment": "sim2real behavioral test", "Runtime": "cloudfront-js-2.0"},
            ConnectionFunctionCode=fn_code,
            Tags={"Items": [{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}]},
        )
    except ClientError as exc:
        raise AssertionError(f"CreateConnectionFunction unavailable in this environment: {exc}") from exc

    fn_id = created["ConnectionFunctionSummary"]["Id"]

    def _cleanup() -> None:
        try:
            cur = cf.get_connection_function(Identifier=fn_id)
            cf.delete_connection_function(Id=fn_id, IfMatch=cur["ETag"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "EntityNotFound":
                raise

    ctx.on_cleanup(_cleanup)

    # success-path contract
    got = cf.get_connection_function(Identifier=fn_id)
    body = got["ConnectionFunctionCode"]
    body_bytes = body.read() if hasattr(body, "read") else body
    assert body_bytes == fn_code, "returned code does not match uploaded code"
    assert "ContentType" in got

    # delete proves gone and unusable (the cleanup delete above was otherwise unasserted)
    cf.delete_connection_function(Id=fn_id, IfMatch=got["ETag"])
    gone_code, gone_message = _error(lambda: cf.get_connection_function(Identifier=fn_id))
    assert gone_code == "EntityNotFound", f"expected EntityNotFound after delete, got {gone_code}"
    assert gone_message == not_found_message, f"expected message {not_found_message!r}, got {gone_message!r}"
    redelete_code, redelete_message = _error(lambda: cf.delete_connection_function(Id=fn_id, IfMatch=got["ETag"]))
    assert redelete_code == "EntityNotFound", f"expected EntityNotFound deleting an already-deleted id, got {redelete_code}"
    assert redelete_message == not_found_message, (
        f"expected message {not_found_message!r}, got {redelete_message!r}"
    )


def _error(fn) -> tuple[str, str]:
    """Run a call AWS refuses; return its (code, message). Raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
