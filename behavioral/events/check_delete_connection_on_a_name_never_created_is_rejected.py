"""delete-connection-on-a-name-never-created-is-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-connection-on-a-name-never-created-is-rejected"
GROUP = "connection"
SERVICES = ["events"]

_SETTLED = ("AUTHORIZED", "CREATE_FAILED")


def _error(fn) -> tuple[str, str]:
    """(code, message) of a call that must fail; an unexpected success raises, naming the result."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteConnection on a name that was never created is refused as not-found, with a real
    connection unaffected, and the same call against that connection succeeds."""
    events = ctx.client("events")
    name = ctx.unique_name("sim2real-behav-conn-")
    created = events.create_connection(
        Name=name,
        AuthorizationType="API_KEY",
        AuthParameters={
            "ApiKeyAuthParameters": {"ApiKeyName": "x-api-key", "ApiKeyValue": "secret-value"}
        },
    )
    ctx.on_cleanup(_teardown(lambda: events.delete_connection(Name=name)))

    deadline = time.monotonic() + 60
    settled = events.describe_connection(Name=name)
    while settled["ConnectionState"] not in _SETTLED and time.monotonic() < deadline:
        time.sleep(1)
        settled = events.describe_connection(Name=name)
    assert settled["ConnectionState"] == "AUTHORIZED", (
        f"the connection must settle AUTHORIZED before the probe, last observed {settled!r}"
    )

    missing = ctx.unique_name("sim2real-behav-conn-")
    code, message = _error(lambda: events.delete_connection(Name=missing))
    assert (code, message) == (
        "ResourceNotFoundException",
        f"Failed to delete the connection(s). Connection '{missing}' does not exist.",
    ), f"deleting a name that was never created must be not-found, got {code!r} {message!r}"

    unaffected = events.describe_connection(Name=name)
    assert unaffected["ConnectionState"] == "AUTHORIZED", (
        f"the refused call on a different name must not touch the real connection, got {unaffected!r}"
    )

    deleted = events.delete_connection(Name=name)
    assert deleted["ConnectionArn"] == created["ConnectionArn"], (
        f"deleting the real connection must act on the ARN it was created with, got {deleted!r}"
    )


def _teardown(undo):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
