"""start-migration-invalid-source-version-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-migration-invalid-source-version-rejected"
GROUP = "negative-classes"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartMigration with the ARN of an Elasticsearch_1.5 or an OpenSearch_2.11 managed domain as the source
    fails with ValidationException and the exact collection-ARN pattern message, and ListMigrations stays
    empty.
    """
    aos = ctx.client("opensearch")
    app_id = _create_application(ctx, aos)

    domains = {
        "old-engine-version": ("Elasticsearch_1.5", _compliant_domain_name(ctx, "sim2real-oldver")),
        "current-engine-version": ("OpenSearch_2.11", _compliant_domain_name(ctx, "sim2real-newver")),
    }

    for label, (engine_version, domain_name) in domains.items():
        domain_arn = aos.create_domain(
            DomainName=domain_name,
            EngineVersion=engine_version,
            ClusterConfig={
                "InstanceType": "t2.small.search",
                "InstanceCount": 1,
                "DedicatedMasterEnabled": False,
                "ZoneAwarenessEnabled": False,
            },
            EBSOptions={"EBSEnabled": True, "VolumeType": "gp2", "VolumeSize": 10},
            TagList=[{"Key": "sim2real-check", "Value": CHECK}],
        )["DomainStatus"]["ARN"]
        ctx.on_cleanup(lambda name=domain_name: _safe(lambda: aos.delete_domain(DomainName=name)))

        code, message = _error(
            lambda arn=domain_arn: aos.start_migration(
                applicationId=app_id,
                migrationOptions={
                    "source": {"datasourceArn": arn},
                    "workspace": {"createWorkspace": True, "name": f"sim2real-ws-{label[:20]}", "type": "SEARCH"},
                },
            )
        )
        assert code == "ValidationException", f"[{label}] expected ValidationException, got {code}"
        expected_message = (
            f"1 validation error detected: Value '{domain_arn}' at 'migrationOptions.source.datasourceArn' "
            "failed to satisfy constraint: Member must satisfy regular expression pattern: "
            r"arn:aws[a-z\-]*:aoss:[a-z0-9\-]+:[0-9]{12}:collection/[a-z0-9]+"
        )
        assert message == expected_message, (
            f"[{label}] expected the message to cite the required OpenSearch Serverless "
            f"collection ARN pattern, got: {message!r}"
        )

    migrations = aos.list_migrations(applicationId=app_id)["migrations"]
    assert migrations == [], f"a migration job was created despite the rejected StartMigration calls: {migrations}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected StartMigration to be rejected, but the call SUCCEEDED")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_application(ctx, aos) -> str:
    raw = ctx.unique_name("sim2real-app-").lower()
    name = "".join(c for c in raw if c.isalnum() or c == "-")[:30].rstrip("-")
    if not name or not name[0].isalpha():
        name = "a" + name
    resp = aos.create_application(name=name[:30], tagList=[{"Key": "sim2real-check", "Value": CHECK}])
    app_id = resp["id"]
    ctx.on_cleanup(lambda: _safe(lambda: aos.delete_application(id=app_id)))
    _wait_application_active(aos, app_id)
    return app_id


def _wait_application_active(aos, app_id: str, timeout_s: float = 120.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = aos.get_application(id=app_id).get("status")
        if last == "ACTIVE":
            return
        if last == "FAILED":
            raise AssertionError(f"application {app_id} entered FAILED status")
        time.sleep(3)
    raise AssertionError(f"application {app_id} never became ACTIVE within {timeout_s}s (last: {last})")


def _compliant_domain_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(f"{prefix}-").lower()
    cleaned = "".join(c for c in raw if c.isalnum() or c == "-")
    cleaned = cleaned[:28].rstrip("-")
    if not cleaned or not cleaned[0].isalpha():
        cleaned = "d" + cleaned
    return cleaned[:28]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
