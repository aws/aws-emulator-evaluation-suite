"""op-contract-get-connection-group."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-connection-group"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetConnectionGroup returns Status/RoutingEndpoint for a created group, 404s on unknown Identifier."""
    cf = ctx.client("cloudfront")

    # distinct error boundary is cheap and has no prerequisites: run it unconditionally.
    code, message = _error(lambda: cf.get_connection_group(Identifier="sim2real-nonexistent-conngroup"))
    assert code == "EntityNotFound", f"unexpected code {code}"
    not_found_message = "The specified connection group does not exist."
    assert message == not_found_message, f"expected message {not_found_message!r}, got {message!r}"

    name = ctx.unique_name("sim2real-conngrp-")
    try:
        created = cf.create_connection_group(Name=name, Enabled=True)
    except ClientError as exc:
        raise AssertionError(f"CreateConnectionGroup unavailable in this environment: {exc}") from exc

    group_id = created["ConnectionGroup"]["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_connection_group(ctx, group_id))

    # success-path contract
    got = cf.get_connection_group(Identifier=group_id)
    assert got["ConnectionGroup"]["Id"] == group_id, (
        f"expected Id {group_id}, got {got['ConnectionGroup']['Id']}"
    )
    assert got["ConnectionGroup"]["Name"] == name, "independent read must reflect the created Name"
    assert got["ConnectionGroup"]["Enabled"] is True, "independent read must reflect the created Enabled"
    assert got["ConnectionGroup"]["Status"] in ("InProgress", "Deployed"), got["ConnectionGroup"]["Status"]
    endpoint = got["ConnectionGroup"]["RoutingEndpoint"]
    assert isinstance(endpoint, str) and len(endpoint) > 0, f"RoutingEndpoint must be a non-empty string, got {endpoint!r}"
    etag = got.get("ETag")
    assert isinstance(etag, str) and len(etag) > 0, f"ETag must be a non-empty token, got {etag!r}"

    # a read must not advance state: an immediate second read is identical.
    again = cf.get_connection_group(Identifier=group_id)
    assert again["ETag"] == etag, "GetConnectionGroup must not mutate ETag on a read"
    assert again["ConnectionGroup"]["Status"] == got["ConnectionGroup"]["Status"], (
        "GetConnectionGroup must not advance Status on a read"
    )


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
