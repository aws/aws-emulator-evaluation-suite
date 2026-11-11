"""start-migration-nonexistent-application-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-migration-nonexistent-application-rejected"
GROUP = "overly-permissive"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartMigration and ListMigrations for an unknown applicationId fail with ResourceNotFoundException
    naming the application, while a real application with the same unresolvable source fails with
    ResourceNotFoundException naming the data source (exact messages).
    """
    opensearch = ctx.client("opensearch")

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    fake_app_id = "zzz" + ctx.unique_name("nope").lower().replace("-", "")[:20]
    fake_app_id = "".join(c for c in fake_app_id if c.isalnum())[:30]
    # MigrationSource.datasourceArn must satisfy the service's own AOSS-collection ARN
    # pattern (arn:aws...:aoss:<region>:<account>:collection/<id>), confirmed on real AWS
    # -- an es:domain ARN, however well-formed, is rejected as ValidationException before
    # applicationId is ever consulted, which would make that ARN shape untestable here.
    placeholder_collection_id = "".join(
        c for c in ctx.unique_name("s2rplch").lower() if c.isalnum()
    )[:20]
    placeholder_arn = f"arn:aws:aoss:{ctx.region}:{account_id}:collection/{placeholder_collection_id}"

    real_app_id = _create_active_application(ctx, opensearch)

    def _migration_options(name: str) -> dict:
        return {
            "source": {"datasourceArn": placeholder_arn},
            "workspace": {"createWorkspace": True, "name": name, "type": "SEARCH"},
        }

    # positive control: ListMigrations succeeds for a real application, proving the
    # applicationId lookup mechanism isn't rejecting every id it is handed.
    migrations = opensearch.list_migrations(applicationId=real_app_id)["migrations"]
    assert migrations == [], f"expected no migrations for a fresh application, got {migrations}"

    # positive control (paired): the identical migrationOptions, with the identical placeholder
    # datasourceArn, clears application lookup once applicationId is real and is instead rejected
    # one stage later on the data source -- proving the rejection below is attributable to the
    # missing application.
    real_code, real_msg = _error_detail(
        lambda: opensearch.start_migration(
            applicationId=real_app_id, migrationOptions=_migration_options("sim2real-ws-pos")
        )
    )
    assert real_code == "ResourceNotFoundException", f"unexpected error code {real_code}: {real_msg}"
    expected_real = f"Data source {placeholder_arn} not found for application {real_app_id}"
    assert real_msg == expected_real, (
        f"expected the real application to clear its own lookup and fail on the "
        f"placeholder data source instead: expected {expected_real!r}, got {real_msg!r}"
    )

    fake_code, fake_msg = _error_detail(
        lambda: opensearch.start_migration(
            applicationId=fake_app_id,
            migrationOptions=_migration_options("sim2real-ws-neg"),
        )
    )
    assert fake_code == "ResourceNotFoundException", f"unexpected error code {fake_code}: {fake_msg}"
    expected_fake = f"Application {fake_app_id} does not exist"
    assert fake_msg == expected_fake, f"expected message {expected_fake!r}, got {fake_msg!r}"

    # No migration job should exist for the bogus application -- listing migrations for
    # it must itself reject with the same not-found semantics, not silently return [].
    list_code, list_msg = _error_detail(lambda: opensearch.list_migrations(applicationId=fake_app_id))
    assert list_code == "ResourceNotFoundException", f"unexpected error code {list_code}: {list_msg}"
    expected_list = f"Application {fake_app_id} not found"
    assert list_msg == expected_list, f"expected message {expected_list!r}, got {list_msg!r}"



def _error_detail(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


def _create_active_application(ctx, opensearch, timeout_s: float = 120.0) -> str:
    raw = ctx.unique_name("sim2real-app-").lower()
    name = "".join(c for c in raw if c.isalnum() or c == "-")[:30].rstrip("-")
    if not name or not name[0].isalpha():
        name = "a" + name
    resp = opensearch.create_application(
        name=name[:30], tagList=[{"Key": "sim2real", "Value": "start-migration-nonexistent-application-rejected"}]
    )
    app_id = resp["id"]
    ctx.on_cleanup(lambda: opensearch.delete_application(id=app_id))
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = opensearch.get_application(id=app_id)["status"]
        if last == "ACTIVE":
            return app_id
        if last == "FAILED":
            raise AssertionError(f"application {app_id} failed to become ACTIVE")
        time.sleep(3)
    raise AssertionError(f"application {app_id} did not become ACTIVE within {timeout_s}s (last: {last})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

