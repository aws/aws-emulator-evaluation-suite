"""op-contract-get-connection-group-by-routing-endpoint."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-connection-group-by-routing-endpoint"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetConnectionGroupByRoutingEndpoint resolves the created group's own endpoint, 404s on an unknown one."""
    cf = ctx.client("cloudfront")

    # distinct error boundary is cheap and has no prerequisites: run it unconditionally.
    not_found_message = "The specified connection group does not exist."
    code, message = _error(
        lambda: cf.get_connection_group_by_routing_endpoint(RoutingEndpoint="sim2real-nonexistent.cloudfront.net")
    )
    assert code == "EntityNotFound", f"unexpected code {code}"
    assert message == not_found_message, f"expected message {not_found_message!r}, got {message!r}"

    name = ctx.unique_name("sim2real-conngrp-rte-")
    try:
        created = cf.create_connection_group(Name=name, Enabled=True)
    except ClientError as exc:
        raise AssertionError(f"CreateConnectionGroup unavailable in this environment: {exc}") from exc

    group_id = created["ConnectionGroup"]["Id"]
    routing_endpoint = created["ConnectionGroup"]["RoutingEndpoint"]
    ctx.on_cleanup(lambda: _disable_and_delete_connection_group(ctx, group_id))

    # success-path contract
    got = cf.get_connection_group_by_routing_endpoint(RoutingEndpoint=routing_endpoint)
    assert got["ConnectionGroup"]["Id"] == group_id, f"expected {group_id}, got {got['ConnectionGroup']['Id']}"
    assert got["ConnectionGroup"]["RoutingEndpoint"] == routing_endpoint, (
        f"expected {routing_endpoint}, got {got['ConnectionGroup']['RoutingEndpoint']}"
    )
    status = got["ConnectionGroup"]["Status"]
    assert status in ("InProgress", "Deployed"), f"unexpected status {status}"
    assert "ETag" in got, "GetConnectionGroupByRoutingEndpoint must return an ETag"

    # the getter must reflect deletion too: disable+delete this check's own group, then prove the
    # same lookup that just succeeded now 404s on the identical routing endpoint.
    _disable_and_delete_connection_group(ctx, group_id)
    code_after_delete, message_after_delete = _error(
        lambda: cf.get_connection_group_by_routing_endpoint(RoutingEndpoint=routing_endpoint)
    )
    assert code_after_delete == "EntityNotFound", f"unexpected code {code_after_delete} after delete"
    assert message_after_delete == not_found_message, (
        f"expected message {not_found_message!r}, got {message_after_delete!r}"
    )


# ===== helpers =====
def _error(fn) -> tuple[str, str]:
    """Run a call AWS refuses; return its (code, message). Raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")


def _disable_and_delete_connection_group(ctx, group_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        current = cf.get_connection_group(Identifier=group_id)
        etag = current["ETag"]
        if current["ConnectionGroup"].get("Enabled", True):
            upd = cf.update_connection_group(Id=group_id, IfMatch=etag, Enabled=False)
            etag = upd["ETag"]
        cf.delete_connection_group(Id=group_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
