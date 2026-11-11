"""overly-permissive-migration-invalid-source-endpoint-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "overly-permissive-migration-invalid-source-endpoint-rejected"
GROUP = "overly-permissive"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartMigration with an unattached domain ARN, a PENDING attached domain ARN or a bare https URI each
    fails with ValidationException and its exact message, and ListMigrations stays empty.
    """
    client = ctx.client("opensearch")
    app_id = _create_application(ctx)
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    attach_arn = f"arn:aws:es:{ctx.region}:{account_id}:domain/{ctx.unique_name('sim2real-src-')}"
    try:
        client.attach_data_source(id=app_id, dataSourceArn=attach_arn)
    except ClientError as err:
        attach_code = err.response["Error"]["Code"]
        if attach_code == "DisabledOperationException":
            raise AssertionError(
                "AttachDataSource is DisabledOperationException in this environment -- the "
                "data-source-attachment/migration capability is not enabled here, so no positive "
                "control can be constructed. Would need that environment prerequisite to close."
            ) from err
        raise AssertionError(f"expected the attach itself to be accepted, got {attach_code!r}") from err
    # Note: a PENDING attachment cannot be detached (DetachDataSource documents a
    # ConflictException for that state) -- DeleteApplication cascading cleanup (registered by
    # _create_application) removes it instead.


    unregistered_arn = f"arn:aws:es:{ctx.region}:{account_id}:domain/{ctx.unique_name('sim2real-unreg-')}"
    unregistered_code, unregistered_message = _error(
        lambda: client.start_migration(
            applicationId=app_id,
            migrationOptions={
                "source": {"datasourceArn": unregistered_arn},
                "workspace": {"createWorkspace": True, "name": ctx.unique_name("sim2real-ws-unreg-")},
            },
        )
    )
    assert unregistered_code == "ValidationException", (
        f"expected ValidationException for a well-formed ARN never attached to this "
        f"application, got {unregistered_code!r}"
    )
    expected_message = _source_pattern_message(unregistered_arn)
    assert unregistered_message == expected_message, (
        f"expected message {expected_message!r}, got {unregistered_message!r}"
    )

    pending_code, pending_message = _error(
        lambda: client.start_migration(
            applicationId=app_id,
            migrationOptions={
                "source": {"datasourceArn": attach_arn},
                "workspace": {"createWorkspace": True, "name": ctx.unique_name("sim2real-ws-pending-")},
            },
        )
    )
    assert pending_code == "ValidationException", (
        f"expected ValidationException for a data source stuck in PENDING (never reaches "
        f"ATTACHED), got {pending_code!r}"
    )
    expected_message = _source_pattern_message(attach_arn)
    assert pending_message == expected_message, f"expected message {expected_message!r}, got {pending_message!r}"

    malformed_options = {
        "source": {"datasourceArn": "https://source-cluster.example.com:9200"},
        "workspace": {"createWorkspace": True, "name": ctx.unique_name("sim2real-ws-")},
    }
    malformed_code, malformed_message = _error(
        lambda: client.start_migration(applicationId=app_id, migrationOptions=malformed_options)
    )
    assert malformed_code == "ValidationException", (
        f"expected ValidationException for a bare connection URI in place of an ARN, got {malformed_code!r}"
    )
    expected_message = _source_pattern_message(malformed_options["source"]["datasourceArn"])
    assert malformed_message == expected_message, (
        f"expected message {expected_message!r}, got {malformed_message!r}"
    )

    # Effect absent: none of the three rejected StartMigration calls created a migration record.
    migrations = client.list_migrations(applicationId=app_id).get("migrations", [])
    assert migrations == [], f"a migration was recorded despite every StartMigration call being rejected: {migrations!r}"


def _source_pattern_message(sent: str) -> str:
    return (
        f"1 validation error detected: Value '{sent}' at 'migrationOptions.source.datasourceArn' "
        "failed to satisfy constraint: Member must satisfy regular expression pattern: "
        "arn:aws[a-z\\-]*:aoss:[a-z0-9\\-]+:[0-9]{12}:collection/[a-z0-9]+"
    )


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _create_application(ctx) -> str:
    client = ctx.client("opensearch")
    name = ctx.unique_name("sim2real-app-")
    resp = client.create_application(name=name, tagList=[{"Key": "sim2real", "Value": "true"}])
    app_id = resp["id"]
    ctx.on_cleanup(lambda: client.delete_application(id=app_id))
    deadline = time.monotonic() + 180
    status = None
    while time.monotonic() < deadline:
        got = _with_throttle_retry(lambda: client.get_application(id=app_id))
        status = got.get("status")
        if status == "ACTIVE":
            return app_id
        if status == "FAILED":
            raise AssertionError(f"application {app_id} entered FAILED status: {got}")
        time.sleep(5)
    raise AssertionError(f"application {app_id} did not reach ACTIVE (last status={status})")


def _with_throttle_retry(fn, *, attempts=6, base_delay=3.0):
    from botocore.exceptions import ClientError

    last_exc = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ThrottlingException":
                raise
            last_exc = exc
            time.sleep(base_delay * (i + 1))
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
