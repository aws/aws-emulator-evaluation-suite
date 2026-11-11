"""e2e-migration-lifecycle-domain-state-consequence."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "e2e-migration-lifecycle-domain-state-consequence"
GROUP = "state-machine"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartMigration with a domain ARN as source raises ValidationException, leaving no migrations,
    while AttachDataSource accepts that ARN; GetMigration on a fake id and DescribeDomain on a
    never-created domain raise ResourceNotFoundException."""
    client = ctx.client("opensearch")

    app_name = ctx.unique_name("sim2real-migapp")
    app_id = client.create_application(
        name=app_name, tagList=[{"Key": "sim2real-check", "Value": CHECK}]
    )["id"]
    ctx.on_cleanup(lambda: client.delete_application(id=app_id))
    _poll_until(
        lambda: client.get_application(id=app_id),
        lambda a: a["status"] == "ACTIVE",
        timeout_s=300.0,
        interval_s=5.0,
    )

    account = ctx.client("sts").get_caller_identity()["Account"]
    domain_shaped_arn = f"arn:aws:es:{ctx.region}:{account}:domain/{ctx.unique_name('s2rmignodom')}"
    workspace_name = ctx.unique_name("sim2real-ws-")

    # The source member's pattern admits only an OpenSearch Serverless collection ARN.
    got = _error(
        lambda: client.start_migration(
            applicationId=app_id,
            migrationOptions={
                "source": {"datasourceArn": domain_shaped_arn},
                "workspace": {"createWorkspace": True, "name": workspace_name},
            },
        )
    )
    expected = (
        "ValidationException",
        f"1 validation error detected: Value '{domain_shaped_arn}' at "
        "'migrationOptions.source.datasourceArn' failed to satisfy constraint: Member must "
        "satisfy regular expression pattern: "
        "arn:aws[a-z\\-]*:aoss:[a-z0-9\\-]+:[0-9]{12}:collection/[a-z0-9]+",
    )
    assert got == expected, (
        f"StartMigration with a domain ARN as datasourceArn should be rejected up front: {got!r}"
    )

    # No migration job was ever created for this application -- the rejection happened before
    # any job record was persisted.
    listed = client.list_migrations(applicationId=app_id)["migrations"]
    assert listed == [], f"ListMigrations should be empty after the rejected StartMigration: {listed!r}"

    # Positive control: AttachDataSource accepts this exact same domain ARN, so the refusal
    # above is specific to StartMigration's source member. A refusal here raises ClientError.
    client.attach_data_source(id=app_id, dataSourceArn=domain_shaped_arn)

    bogus_migration_id = f"mig-{ctx.unique_name('x')}"
    got_get = _error(lambda: client.get_migration(migrationId=bogus_migration_id))
    assert got_get == ("ResourceNotFoundException", "Application mig not found"), (
        f"unexpected refusal for a bogus migrationId: {got_get!r}"
    )

    bogus_domain_name = ctx.unique_name("s2rmignodom2").lower()
    got_domain = _error(lambda: client.describe_domain(DomainName=bogus_domain_name))
    assert got_domain == ("ResourceNotFoundException", f"Domain not found: {bogus_domain_name}"), (
        f"unexpected refusal describing a domain that was never created: {got_domain!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed: {last!r}")


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

