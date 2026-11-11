"""delete-connection-eventually-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-connection-eventually-not-found"
GROUP = 'connection'
SERVICES = ['events']

_SETTLED = ("AUTHORIZED", "CREATE_FAILED")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteConnection answers DELETING and is asynchronous: DescribeConnection converges on
    ResourceNotFoundException with its exact message, and a later UpdateConnection is not-found."""
    ev = ctx.client("events")
    name = ctx.unique_name("sim2real-behav-conn-")
    ev.create_connection(
        Name=name,
        AuthorizationType="API_KEY",
        AuthParameters={
            "ApiKeyAuthParameters": {"ApiKeyName": "x-api-key", "ApiKeyValue": "secret-value"}
        },
    )
    ctx.on_cleanup(lambda: _delete_quietly(ev, name))

    deadline = time.monotonic() + 60
    settled = ev.describe_connection(Name=name)
    while settled["ConnectionState"] not in _SETTLED and time.monotonic() < deadline:
        time.sleep(1)
        settled = ev.describe_connection(Name=name)
    assert settled["ConnectionState"] in _SETTLED, (
        f"connection must settle out of CREATING/AUTHORIZING before delete, last observed {settled}"
    )

    deleted = ev.delete_connection(Name=name)
    assert deleted["ConnectionState"] == "DELETING", (
        f"DeleteConnection should report the connection entering DELETING, got {deleted}"
    )

    deadline = time.monotonic() + 180
    final = _probe(ev, name)
    while final[0] != "ResourceNotFoundException" and time.monotonic() < deadline:
        time.sleep(5)
        final = _probe(ev, name)
    assert final == (
        "ResourceNotFoundException",
        f"Failed to describe the connection(s). Connection '{name}' does not exist.",
    ), f"connection must eventually be gone, last observed {final}"

    try:
        ev.update_connection(Name=name, Description="probe-after-delete")
    except ClientError as e:
        mutate = (e.response["Error"]["Code"], e.response["Error"]["Message"])
    else:
        raise AssertionError("UpdateConnection on the deleted connection's name SUCCEEDED")
    assert mutate == (
        "ResourceNotFoundException",
        f"Failed to update the connection(s). Connection '{name}' does not exist.",
    ), f"a mutation on the deleted connection's name must also be rejected as not-found, got {mutate}"


def _probe(ev, name: str) -> tuple[str, str]:
    """The connection's state, or the (code, message) of the DescribeConnection refusal."""
    try:
        return (ev.describe_connection(Name=name)["ConnectionState"], "")
    except ClientError as e:
        return (e.response["Error"]["Code"], e.response["Error"]["Message"])


def _delete_quietly(ev, name: str) -> None:
    try:
        ev.delete_connection(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
