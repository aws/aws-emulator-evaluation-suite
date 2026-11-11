"""s3-table-integration-associate-list-disassociate."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-table-integration-associate-list-disassociate"
GROUP = "state-machine"
SERVICES = ["logs"]


def _never_ready(msg: str):
    """A resource accepted but never ready; returned so a call site keeps ``from exc`` chaining."""
    return AssertionError(msg)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:logs-s3-table-integration")
def run(ctx) -> None:
    """AssociateSourceToS3TableIntegration adds a source that appears in
    ListSourcesForS3TableIntegration and is removed by
    DisassociateSourceFromS3TableIntegration."""
    logs = ctx.client("logs")

    if not hasattr(logs, "associate_source_to_s3_table_integration"):
        raise AssertionError("unreachable: this boto3 version lacks S3 Table Integration APIs")

    try:
        obs = ctx.client("observabilityadmin")
    except Exception as exc:  # noqa: BLE001 - unknown-service errors vary by botocore version
        raise AssertionError(f"unreachable: observabilityadmin client unavailable: {exc}") from exc

    # An S3 Table Integration is a one-per-account singleton: CreateS3TableIntegration raises
    # ConflictException if one exists, and this check then fails rather than deleting it.

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-s3tbl-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "logs.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    try:
        role_arn = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )["Role"]["Arn"]
    except ClientError as exc:
        raise AssertionError(f"cannot create prerequisite IAM role: {exc}") from exc
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))

    policy_document = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3tables:*", "s3:*"], "Resource": "*"}],
    }
    try:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="sim2real-s3tables-access",
            PolicyDocument=json.dumps(policy_document),
        )
    except ClientError as exc:
        raise AssertionError(f"cannot attach prerequisite IAM inline policy: {exc}") from exc

    integration_arn = None
    last_exc: Exception | None = None
    for attempt in range(6):
        try:
            integration_arn = obs.create_s3_table_integration(
                RoleArn=role_arn, Encryption={"SseAlgorithm": "AES256"}
            )["Arn"]
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ConflictException":
                raise AssertionError(
                    "account already has an S3 Table Integration (one-per-account limit)"
                ) from exc
            last_exc = exc
            if code in ("AccessDeniedException", "ValidationException") and attempt < 5:
                time.sleep(5)  # allow the new IAM role/policy to propagate
                continue
            raise AssertionError(f"could not create prerequisite S3 Table Integration: {exc}") from exc
    if integration_arn is None:
        raise AssertionError(f"could not create prerequisite S3 Table Integration: {last_exc}")

    ctx.on_cleanup(lambda: _delete_s3_table_integration(obs, integration_arn))

    status = _poll_until(
        lambda: obs.get_s3_table_integration(Arn=integration_arn)["Status"],
        lambda s: s == "ACTIVE",
        timeout_s=60,
        interval_s=3,
    )
    if status != "ACTIVE":
        raise _never_ready(
            f"S3 Table Integration never reached ACTIVE (status={status!r})",
        )

    # Real AWS rejects a dataSource name containing anything but lowercase letters, digits, and
    # underscores ("Source name must only contain letters, numbers, and underscores") -- even
    # though ctx.unique_name's default prefixes use hyphens freely and boto3 doesn't enforce
    # case. Use an all-lowercase, hyphen-free prefix (and lower() the generated hex suffix too,
    # since uppercase letters trip the same validation on real AWS) so the name always passes.
    source_name = ctx.unique_name("sim2reals3tblsrc").lower()
    # The service rejects a dataSource with a null "type" (real AWS enforces this even though
    # it isn't marked as a required member in the published shape), so a type must always be
    # supplied alongside the name. Real AWS also enforces the same lowercase
    # letters/numbers/underscores constraint on "type" as it does on "name" (an uppercase value
    # like "APPLICATION_LOGS" is rejected with "Source type must only contain letters, numbers,
    # and underscores"), so use an all-lowercase type value.
    assoc = logs.associate_source_to_s3_table_integration(
        integrationArn=integration_arn,
        dataSource={"name": source_name, "type": "application_logs"},
    )
    identifier = assoc["identifier"]
    ctx.on_cleanup(lambda: _disassociate(logs, identifier))

    listed = logs.list_sources_for_s3_table_integration(integrationArn=integration_arn)
    identifiers = [s["identifier"] for s in listed.get("sources", [])]
    assert identifier in identifiers, (
        f"{identifier} missing from ListSourcesForS3TableIntegration: {identifiers}"
    )

    logs.disassociate_source_from_s3_table_integration(identifier=identifier)

    # Disassociation is processed asynchronously on real AWS: the identifier can still
    # briefly appear in ListSourcesForS3TableIntegration immediately afterwards, so poll
    # until it disappears (bounded) instead of asserting on a single immediate read.
    def _list_identifiers() -> list[str]:
        listed_after = logs.list_sources_for_s3_table_integration(integrationArn=integration_arn)
        return [s["identifier"] for s in listed_after.get("sources", [])]

    identifiers_after = _poll_until(
        _list_identifiers,
        lambda ids: identifier not in ids,
        timeout_s=60,
        interval_s=3,
    )
    assert identifier not in identifiers_after, f"{identifier} still present after disassociate"

    try:
        logs.disassociate_source_from_s3_table_integration(identifier=identifier)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException disassociating already-removed "
            f"identifier {identifier}, got {code!r}: {message!r}"
        )
        assert message == f"Association not found for identifier: {identifier}", (
            f"unexpected already-removed association message: {message!r}"
        )
    else:
        raise AssertionError(
            f"disassociating already-removed identifier {identifier} unexpectedly succeeded"
        )


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 3.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _disassociate(logs_client: Any, identifier: str) -> None:
    try:
        logs_client.disassociate_source_from_s3_table_integration(identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_s3_table_integration(obs_client: Any, integration_arn: str) -> None:
    try:
        obs_client.delete_s3_table_integration(Arn=integration_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_role(ctx: Any, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-s3tables-access")
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
