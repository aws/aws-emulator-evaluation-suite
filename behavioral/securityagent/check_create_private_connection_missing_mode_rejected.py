"""create-private-connection-missing-mode-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-private-connection-missing-mode-rejected"
GROUP = "overly-permissive"
SERVICES = ["securityagent"]


def _error(fn):
    """Returns the server-side error (Code, Message), or raises if the call unexpectedly succeeds."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError("call succeeded, expected a rejection")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePrivateConnection with an empty `mode` union, sent with client-side validation off so it
    reaches the service, is refused with ValidationException and its exact message, and no connection
    of that name exists; a security requirement pack create/delete round trip still works."""
    sa = ctx.client("securityagent")
    raw = ctx.client("securityagent", config=Config(parameter_validation=False))
    name = ctx.unique_name("sim2real-behav-privconn-")

    code, message = _error(lambda: raw.create_private_connection(privateConnectionName=name, mode={}))
    assert code == "ValidationException", f"unexpected code {code!r}"
    expected = "Private Connection mode must specify either serviceManaged or selfManaged"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: nothing was created under this name
    matches = [c for c in sa.list_private_connections()["privateConnections"] if c["name"] == name]
    assert matches == []

    # positive control: create_private_connection's own service/account path is
    # generally functional (create+delete round trip on a sibling resource type),
    # proved by an independent read rather than the absence of an exception
    pack_id = sa.create_security_requirement_pack(name=ctx.unique_name("sim2real-behav-pack-"))["packId"]
    assert sa.get_security_requirement_pack(packId=pack_id)["packId"] == pack_id
    sa.delete_security_requirement_pack(packId=pack_id)
    code, message = _error(lambda: sa.get_security_requirement_pack(packId=pack_id))
    assert code == "ResourceNotFoundException", f"unexpected code {code!r}"
    expected = f"No security requirement pack found for ID: {pack_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

