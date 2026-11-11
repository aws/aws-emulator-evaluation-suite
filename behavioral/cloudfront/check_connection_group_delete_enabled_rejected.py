"""connection-group-delete-enabled-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "connection-group-delete-enabled-rejected"
GROUP = "state-machine"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting a connection group that is still Enabled is rejected until it's disabled first."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-conngrp-rej-")[:64]

    created = cf.create_connection_group(
        Name=name, Enabled=True, Tags={"Items": [{"Key": "sim2real-check", "Value": CHECK}]}
    )
    group_id = created["ConnectionGroup"]["Id"]
    ctx.on_cleanup(lambda: _delete_group(cf, group_id))

    code, msg = _error(lambda: cf.delete_connection_group(Id=group_id, IfMatch=created["ETag"]))
    assert code == "ResourceNotDisabled", code
    not_disabled_msg = "You must disable the specified connection group before you can delete it."
    assert msg == not_disabled_msg, f"expected message {not_disabled_msg!r}, got {msg!r}"

    # effect absent: the rejected delete left the group in place and still enabled
    got = cf.get_connection_group(Identifier=group_id)
    assert got["ConnectionGroup"]["Enabled"] is True, "must remain enabled after rejected delete"

    # once disabled, deletion succeeds
    disabled = cf.update_connection_group(Id=group_id, IfMatch=got["ETag"], Enabled=False)
    assert disabled["ConnectionGroup"]["Enabled"] is False, disabled["ConnectionGroup"].get("Enabled")
    cf.delete_connection_group(Id=group_id, IfMatch=disabled["ETag"])

    code_after, msg_after = _error(lambda: cf.get_connection_group(Identifier=group_id))
    assert code_after == "EntityNotFound", code_after
    not_found_msg = "The specified connection group does not exist."
    assert msg_after == not_found_msg, f"expected message {not_found_msg!r}, got {msg_after!r}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_group(cf, group_id):
    from botocore.exceptions import ClientError

    try:
        got = cf.get_connection_group(Identifier=group_id)
        grp = got["ConnectionGroup"]
        etag = got["ETag"]
        if grp.get("Enabled"):
            etag = cf.update_connection_group(Id=group_id, IfMatch=etag, Enabled=False)["ETag"]
        cf.delete_connection_group(Id=group_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
