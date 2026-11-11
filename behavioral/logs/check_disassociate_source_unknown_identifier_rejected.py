"""disassociate-source-unknown-identifier-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disassociate-source-unknown-identifier-rejected"
GROUP = "overly-permissive"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:logs-s3-table-integration")
def run(ctx) -> None:
    """DisassociateSourceFromS3TableIntegration fails with ResourceNotFoundException for an
    identifier already disassociated and for one never issued; the first disassociate succeeds.
    """
    logs = ctx.client("logs")
    iam = ctx.client("iam")
    obs = ctx.client("observabilityadmin")
    account = ctx.client("sts").get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-behav-s3tblu-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "logs.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:SourceAccount": account}},
            }
        ],
    }
    try:
        role_arn = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Tags=[{"Key": "sim2real", "Value": "true"}],
        )["Role"]["Arn"]
    except ClientError as exc:
        raise AssertionError(f"cannot create prerequisite IAM role: {exc}") from exc
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))

    try:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="sim2real-s3tables-access",
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Allow", "Action": ["s3tables:*"], "Resource": "*"}
                    ],
                }
            ),
        )
    except ClientError as exc:
        raise AssertionError(f"cannot attach prerequisite IAM inline policy: {exc}") from exc

    integration_arn, created = _create_or_adopt_integration(obs, role_arn)
    if integration_arn is None:
        raise AssertionError("could not create or adopt a prerequisite S3 Table Integration")
    if created:
        ctx.on_cleanup(lambda: obs.delete_s3_table_integration(Arn=integration_arn))

    status = _poll_until(
        lambda: obs.get_s3_table_integration(Arn=integration_arn)["Status"],
        lambda s: s == "ACTIVE",
        timeout_s=180.0,
        interval_s=5.0,
        description="S3 Table Integration reaches ACTIVE",
    )
    assert status == "ACTIVE", f"S3 Table Integration never reached ACTIVE (last status={status!r})"

    source_name = ctx.unique_name("sim2reals3tblusrc").lower()
    identifier = logs.associate_source_to_s3_table_integration(
        integrationArn=integration_arn,
        dataSource={"name": source_name, "type": "application_logs"},
    )["identifier"]
    assert identifier, f"AssociateSourceToS3TableIntegration returned no identifier: {identifier!r}"

    # Positive control: the identifier disassociates cleanly exactly once.
    logs.disassociate_source_from_s3_table_integration(identifier=identifier)

    def _list_identifiers() -> list[str]:
        listed = logs.list_sources_for_s3_table_integration(integrationArn=integration_arn)
        return [s["identifier"] for s in listed.get("sources", [])]

    identifiers_after = _poll_until(
        _list_identifiers,
        lambda ids: identifier not in ids,
        timeout_s=60.0,
        interval_s=3.0,
        description="disassociated source disappears from ListSourcesForS3TableIntegration",
    )
    assert identifier not in identifiers_after, f"{identifier} still listed after disassociate"

    # Repeating the identical call against the now-dead identifier must be rejected.
    repeat_code, repeat_message = _error(
        lambda: logs.disassociate_source_from_s3_table_integration(identifier=identifier)
    )
    assert repeat_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException disassociating an already-removed "
        f"identifier, got {repeat_code!r}"
    )
    assert repeat_message == f"Association not found for identifier: {identifier}", (
        f"unexpected message disassociating an already-removed identifier: {repeat_message!r}"
    )

    # A never-issued identifier is rejected with the same error code.
    bogus_identifier = ctx.unique_name("sim2real-s3tbl-src-missing-")
    bogus_code, bogus_message = _error(
        lambda: logs.disassociate_source_from_s3_table_integration(identifier=bogus_identifier)
    )
    assert bogus_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for an unknown association identifier, "
        f"got {bogus_code!r}"
    )
    assert bogus_message == f"Association not found for identifier: {bogus_identifier}", (
        f"unexpected message for an unknown association identifier: {bogus_message!r}"
    )


def _create_or_adopt_integration(obs, role_arn):
    """Create the integration, or adopt the existing one: it is a one-per-account singleton
    (ConflictException). Returns (arn, created_by_this_check)."""
    try:
        return (
            obs.create_s3_table_integration(
                RoleArn=role_arn,
                Encryption={"SseAlgorithm": "AES256"},
                Tags={"sim2real": "true"},
            )["Arn"],
            True,
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code == "ConflictException":
            existing = obs.list_s3_table_integrations().get("IntegrationSummaries", [])
            if existing:
                return existing[0]["Arn"], False
            raise AssertionError(
                "CreateS3TableIntegration reported ConflictException but "
                "ListS3TableIntegrations shows none to adopt"
            ) from exc
        if code in ("AccessDeniedException", "ValidationException", "InvalidParameterException"):
            return None, False
        raise


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_role(iam, role_name: str) -> None:
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
