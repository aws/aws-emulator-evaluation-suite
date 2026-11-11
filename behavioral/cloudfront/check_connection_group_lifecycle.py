"""connection-group-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "connection-group-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudfront"]

# NOTE: unlike a distribution, deleting/updating a connection group does NOT require the resource's
# global Status to reach "Deployed" first — only the current ETag (Enabled=False for delete). A
# connection group's underlying Anycast IP allocation can take many minutes to fully deploy — far
# past this suite's fixed per-check timeout — so this check must never gate a mutation on reaching
# "Deployed"; it only polls (briefly, bounded) for the resource to disappear after delete, which is
# a much faster local effect.
_GONE_TIMEOUT_S = 120.0
_GONE_INTERVAL_S = 5.0


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Connection groups support create->get->update->delete->list and resolve by routing endpoint."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-conngrp-")

    if not hasattr(cf, "create_connection_group"):
        raise AssertionError("installed botocore does not support CreateConnectionGroup")

    try:
        created = cf.create_connection_group(
            Name=name,
            Enabled=True,
            Ipv6Enabled=True,
            Tags={"Items": [{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}]},
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code in ("UnsupportedOperation", "AccessDenied", "EntityLimitExceeded"):
            raise AssertionError(f"connection groups unavailable for this account/region: {code}") from exc
        raise

    group_id = created["ConnectionGroup"]["Id"]
    routing_endpoint = created["ConnectionGroup"]["RoutingEndpoint"]
    assert routing_endpoint, "RoutingEndpoint must be assigned on create"
    assert created["ConnectionGroup"]["IsDefault"] is False

    def _cleanup() -> None:
        try:
            cfg = cf.get_connection_group(Identifier=group_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "EntityNotFound":
                return
            raise
        etag = cfg["ETag"]
        if cfg["ConnectionGroup"]["Enabled"]:
            etag = cf.update_connection_group(Id=group_id, IfMatch=etag, Enabled=False)["ETag"]
        cf.delete_connection_group(Id=group_id, IfMatch=etag)

    ctx.on_cleanup(_cleanup)

    got = cf.get_connection_group(Identifier=group_id)
    assert got["ConnectionGroup"]["Name"] == name
    assert got["ConnectionGroup"]["Enabled"] is True

    by_endpoint = cf.get_connection_group_by_routing_endpoint(RoutingEndpoint=routing_endpoint)
    assert by_endpoint["ConnectionGroup"]["Id"] == group_id

    listed = cf.list_connection_groups()
    ids = [g["Id"] for g in listed.get("ConnectionGroups", [])]
    assert group_id in ids, "newly created connection group must appear in ListConnectionGroups"

    disabled = cf.update_connection_group(Id=group_id, IfMatch=got["ETag"], Enabled=False)
    assert disabled["ConnectionGroup"]["Enabled"] is False

    cf.delete_connection_group(Id=group_id, IfMatch=disabled["ETag"])

    deleted = _wait_connection_group_gone(ctx, group_id)
    assert deleted

    mutate_code, mutate_msg = _error(
        lambda: cf.update_connection_group(Id=group_id, IfMatch=disabled["ETag"], Enabled=True)
    )
    assert mutate_code == "EntityNotFound", f"mutation on deleted group must 404, got {mutate_code}"
    not_found_msg = "The specified connection group does not exist."
    assert mutate_msg == not_found_msg, f"expected message {not_found_msg!r}, got {mutate_msg!r}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _wait_connection_group_gone(ctx, group_id: str, timeout_s: float = _GONE_TIMEOUT_S) -> bool:
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            cf.get_connection_group(Identifier=group_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "EntityNotFound":
                return True
            raise
        if time.monotonic() >= deadline:
            return False
        time.sleep(_GONE_INTERVAL_S)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
