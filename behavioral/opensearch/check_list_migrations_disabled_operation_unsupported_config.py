"""list-migrations-disabled-operation-unsupported-config."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-migrations-disabled-operation-unsupported-config"
GROUP = "error-semantics"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListMigrations for an ACTIVE application without migrations returns an empty list, while an
    applicationId outside [a-z0-9-]{3,30} fails with ValidationException and its exact message.
    """
    client = ctx.client("opensearch")
    app_id = _create_application(ctx)

    empty = client.list_migrations(applicationId=app_id)
    assert empty.get("migrations", []) == [], (
        f"expected an empty migrations list for a fresh application, got {empty!r}"
    )

    malformed_application_id = "THIS-IS-NOT-VALID!!"  # upper-case + '!' violate [a-z0-9-]{3,30}
    got = _error(lambda: client.list_migrations(applicationId=malformed_application_id))
    expected = (
        "ValidationException",
        f"1 validation error detected: Value '{malformed_application_id}' at 'applicationId' "
        "failed to satisfy constraint: Member must satisfy regular expression pattern: "
        "[a-z0-9-]{3,30}",
    )
    assert got == expected, (
        f"expected {expected!r} for an applicationId violating the documented shape, got {got!r}"
    )

    still = client.get_application(id=app_id)
    assert still["status"] == "ACTIVE", f"application unexpectedly affected: {still}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_application(ctx) -> str:
    client = ctx.client("opensearch")
    name = ctx.unique_name("sim2real-app-")
    resp = client.create_application(name=name, tagList=[{"Key": "sim2real", "Value": "audit"}])
    app_id = resp["id"]
    ctx.on_cleanup(lambda: client.delete_application(id=app_id))
    deadline = time.monotonic() + 120
    status = None
    while time.monotonic() < deadline:
        got = client.get_application(id=app_id)
        status = got.get("status")
        if status == "ACTIVE":
            return app_id
        if status == "FAILED":
            raise AssertionError(f"application {app_id} entered FAILED status: {got}")
        time.sleep(3)
    raise AssertionError(f"application {app_id} did not reach ACTIVE (last status={status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
