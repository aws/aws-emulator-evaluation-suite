"""s3-table-integration-source-lifecycle-transitions."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "s3-table-integration-source-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["logs"]

# The modelled S3TableIntegrationSourceStatus enum (com.amazonaws.cloudwatchlogs).
_SOURCE_STATUSES = {"ACTIVE", "UNHEALTHY", "FAILED", "DATA_SOURCE_DELETE_IN_PROGRESS"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:logs-s3-table-integration")
def run(ctx) -> None:
    """AssociateSourceToS3TableIntegration attaches a log source that becomes
    visible via ListSourcesForS3TableIntegration; DisassociateSourceFromS3TableIntegration
    removes it again."""
    iam = ctx.client("iam")
    admin = ctx.client("observabilityadmin")
    logs = ctx.client("logs")

    role_name = ctx.unique_name("sim2real-behav-s3tbl-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": ["logs.amazonaws.com", "observabilityadmin.amazonaws.com"]},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    try:
        role_arn = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Tags=[{"Key": "sim2real", "Value": "s3-table-integration-source-lifecycle-transitions"}],
        )["Role"]["Arn"]
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="s3tables-write",
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Allow", "Action": ["s3tables:*", "glue:*"], "Resource": "*"}
                    ],
                }
            ),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3tables-write"))
    except Exception as exc:  # pragma: no cover - environment-dependent prerequisite
        raise AssertionError(f"could not provision prerequisite IAM role: {exc}") from None

    try:
        # New roles take a moment to propagate before they can be referenced
        # cross-service: poll the actual dependent call to a success condition
        # (bounded) instead of sleeping a fixed amount.
        integration_arn = _retry_until_success(
            lambda: admin.create_s3_table_integration(
                RoleArn=role_arn,
                Encryption={"SseAlgorithm": "AES256"},
                Tags={"sim2real": "s3-table-integration-source-lifecycle-transitions"},
            )["Arn"],
            retryable_codes={"AccessDeniedException", "ValidationException", "InvalidParameterException"},
            timeout_s=120,
            interval_s=5,
        )
    except Exception as exc:
        raise AssertionError(f"CreateS3TableIntegration unavailable/denied in this account: {exc}") from None
    ctx.on_cleanup(lambda: admin.delete_s3_table_integration(Arn=integration_arn))

    # The integration resource itself transitions PENDING -> ACTIVE before it can accept a
    # source association; associating against a not-yet-ACTIVE integration is the same
    # cross-service propagation lag CreateS3TableIntegration retries above, one level down.
    status = _poll_until(
        lambda: admin.get_s3_table_integration(Arn=integration_arn)["Status"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
        interval_s=5,
    )
    assert status == "ACTIVE", f"S3 Table Integration never reached ACTIVE (last status={status!r})"

    # Real AWS rejects a dataSource "name" containing anything but letters, digits and
    # underscores ("Source name must only contain letters, numbers, and underscores"), so a
    # hyphen-free prefix is required even though ctx.unique_name's defaults use hyphens freely.
    source_name = ctx.unique_name("sim2realbehavs3tblsrc")
    # Real AWS rejects a dataSource with a null "type" ("Value null at 'sourceType' failed to
    # satisfy constraint: Member must not be null") even though the published shape does not mark
    # it required; empirically it must be a lowercase-letters/digits/underscores value.
    identifier = logs.associate_source_to_s3_table_integration(
        integrationArn=integration_arn,
        dataSource={"name": source_name, "type": "application_logs"},
    )["identifier"]

    def sources() -> list[dict]:
        return logs.list_sources_for_s3_table_integration(integrationArn=integration_arn)["sources"]

    def has_identifier(items: list[dict]) -> bool:
        return any(s.get("identifier") == identifier for s in items)

    present = _poll_until(sources, has_identifier, timeout_s=60, interval_s=3)
    assert has_identifier(present), f"association {identifier} never appeared in ListSourcesForS3TableIntegration"

    found = next(s for s in present if s.get("identifier") == identifier)
    assert found.get("status") in _SOURCE_STATUSES, (
        f"association {identifier} reported an unrecognized status {found.get('status')!r}: {found!r}"
    )

    logs.disassociate_source_from_s3_table_integration(identifier=identifier)

    absent = _poll_until(sources, lambda items: not has_identifier(items), timeout_s=60, interval_s=3)
    assert not has_identifier(absent), f"association {identifier} still present after disassociate"


def _retry_until_success(fn, retryable_codes, *, timeout_s=60.0, interval_s=3.0):
    """Poll a dependent call to a success condition, retrying only on the
    given (transient/propagation-related) error codes, bounded by timeout_s."""
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except Exception as exc:  # botocore.exceptions.ClientError
            response = getattr(exc, "response", None)
            code = response.get("Error", {}).get("Code") if response is not None else None
            if code not in retryable_codes:
                raise
            last_exc = exc
            time.sleep(interval_s)
    assert last_exc is not None, f"timed out after {timeout_s}s without a single retryable attempt"
    raise last_exc


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
