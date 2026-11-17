"""update-connection-malformed-kms-key-identifier-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-connection-malformed-kms-key-identifier-rejected"
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
    """UpdateConnection refuses a KmsKeyIdentifier that does not match its documented pattern,
    leaving the connection's description unchanged, while a plain description update succeeds."""
    events = ctx.client("events")
    name = ctx.unique_name("sim2real-behav-conn-")
    events.create_connection(
        Name=name,
        Description="sim2real original description",
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

    bogus_key = "!!!not-a-kms-identifier!!!"
    code, message = _error(lambda: events.update_connection(Name=name, KmsKeyIdentifier=bogus_key))
    assert (code, message) == (
        "ValidationException",
        f"1 validation error detected: Value '{bogus_key}' at 'kmsKeyIdentifier' failed to satisfy "
        r"constraint: Member must satisfy regular expression pattern: ^[a-zA-Z0-9_\-/:]*$",
    ), f"the malformed KmsKeyIdentifier must be refused exactly, got {code!r} {message!r}"

    unaffected = events.describe_connection(Name=name)
    assert unaffected["Description"] == "sim2real original description", (
        f"the refused update must leave the description unchanged, got {unaffected!r}"
    )

    updated = events.update_connection(Name=name, Description="sim2real updated description")
    assert updated["ConnectionState"] == "AUTHORIZED", (
        f"a plain description update must leave an authorized connection authorized, got {updated!r}"
    )
    final = events.describe_connection(Name=name)
    assert final["Description"] == "sim2real updated description", (
        f"the accepted update must change the description, got {final!r}"
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
