"""op-contract-create-connection-group."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-create-connection-group"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateConnectionGroup: allocates a real RoutingEndpoint for the group, that
    allocation is visible on an independent GetConnectionGroup read, and a duplicate
    Name is rejected with EntityAlreadyExists without creating a second entity."""

    cf = ctx.client("cloudfront")
    if not hasattr(cf, "create_connection_group"):
        raise AssertionError("create_connection_group not in installed botocore")

    name = ctx.unique_name("sim2real-behav-conngrp-")
    tag_items = {"Items": [{"Key": "sim2real-check", "Value": CHECK}]}

    try:
        resp = cf.create_connection_group(Name=name, Enabled=False, Tags=tag_items)
    except Exception as exc:
        err_code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        if err_code == "UnsupportedOperation":
            raise AssertionError("connection groups not enabled on this account")
        raise

    group = resp["ConnectionGroup"]
    group_id = group["Id"]
    etag = resp["ETag"]
    ctx.on_cleanup(lambda: cf.delete_connection_group(Id=group_id, IfMatch=etag))

    assert group["Name"] == name
    assert group["Enabled"] is False
    assert group["RoutingEndpoint"], "RoutingEndpoint must be allocated"
    assert group["Arn"].endswith(group_id)

    # Independent read: confirm create's own response against GetConnectionGroup, a different
    # operation, at the destination.
    got = cf.get_connection_group(Identifier=group_id)["ConnectionGroup"]
    assert got["Id"] == group_id
    assert got["Name"] == name, f"expected {name!r} on read, got {got['Name']!r}"
    assert got["Enabled"] is False
    assert got["RoutingEndpoint"] == group["RoutingEndpoint"]
    assert got["Arn"] == group["Arn"]

    # Error boundary: duplicate Name is rejected.
    err_code, err_message = _error(lambda: cf.create_connection_group(Name=name))
    assert err_code == "EntityAlreadyExists", f"expected EntityAlreadyExists, got {err_code}"
    expected = "A connection group with the same name already exists in this AWS account."
    assert err_message == expected, f"expected message {expected!r}, got {err_message!r}"

    # Effect absent: the rejected duplicate must not have created a second entity,
    # and the original must be untouched.
    listed = cf.list_connection_groups().get("ConnectionGroups", [])
    matching = [g for g in listed if g["Name"] == name]
    assert len(matching) == 1, f"expected exactly 1 connection group named {name!r}, found {len(matching)}"
    assert matching[0]["Id"] == group_id
    original = cf.get_connection_group(Identifier=group_id)["ConnectionGroup"]
    assert original["Enabled"] is False, "original connection group must be untouched by the rejected create"


def _error(fn):
    """Call fn(); return the ClientError (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
