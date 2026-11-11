"""telemetry-pipeline-source-type-immutable-update-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "telemetry-pipeline-source-type-immutable-update-rejected"
GROUP = "overly-permissive"
SERVICES = ["observabilityadmin"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateTelemetryPipeline changing the source type fails with ValidationException "Validation
    errors found" and keeps the cloudwatch_logs source; an update that only changes the processors
    persists."""
    client = ctx.client("observabilityadmin")
    name = _pipeline_name(ctx)
    role_arn = _create_source_role(ctx)

    created = client.create_telemetry_pipeline(
        Name=name,
        Configuration={"Body": _cloudwatch_logs_body(role_arn)},
        Tags={"sim2real": CHECK},
    )
    arn = created["Arn"]
    ctx.on_cleanup(lambda: _delete_pipeline_ignore_not_found(client, arn))

    # Wait for the pipeline to leave the transient CREATING state so the update attempt
    # below fails on the immutability rule itself, not on a concurrent-modification conflict.
    _wait_pipeline_terminal(client, arn, timeout_s=150)

    s3_source_body = (
        "pipeline:\n"
        "  source:\n"
        "    s3:\n"
        "      aws:\n"
        f'        sts_role_arn: "{role_arn}"\n'
        f'        region: "{ctx.region}"\n'
        '      notification_type: "sqs"\n'
        "  sink:\n"
        "    - cloudwatch_logs:\n"
        '        log_group: "@original"\n'
    )
    code, message = _client_error(
        lambda: client.update_telemetry_pipeline(
            PipelineIdentifier=arn, Configuration={"Body": s3_source_body}
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == "Validation errors found", (
        f"expected the message 'Validation errors found', got {message!r}"
    )

    unchanged = client.get_telemetry_pipeline(PipelineIdentifier=arn)["Pipeline"]
    body_after_rejected_update = unchanged["Configuration"]["Body"]
    assert "cloudwatch_logs" in body_after_rejected_update, (
        f"expected original cloudwatch_logs source to survive the rejected update, "
        f"got body={body_after_rejected_update!r}"
    )
    assert "s3:" not in body_after_rejected_update, (
        f"expected the rejected source-type change to leave no s3 source behind, "
        f"got body={body_after_rejected_update!r}"
    )

    # positive control: same source type, modified processor list -> accepted
    updated_body = _cloudwatch_logs_body(
        role_arn, extra_processor='    - uppercase_string:\n        with_keys:\n          - level\n'
    )
    client.update_telemetry_pipeline(PipelineIdentifier=arn, Configuration={"Body": updated_body})

    persisted = client.get_telemetry_pipeline(PipelineIdentifier=arn)["Pipeline"]
    persisted_body = persisted["Configuration"]["Body"]
    assert "cloudwatch_logs" in persisted_body, (
        f"expected the same-source-type positive control to keep cloudwatch_logs, "
        f"got body={persisted_body!r}"
    )
    assert "uppercase_string" in persisted_body, (
        f"expected the positive control's processor-list change to persist, "
        f"got body={persisted_body!r}"
    )


def _create_source_role(ctx) -> str:
    # A role that actually EXISTS and trusts the CloudWatch Logs service principal, so
    # CreateTelemetryPipeline's role validation succeeds.
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-oa-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "logs.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    created_role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = created_role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_ignore_not_found(iam, role_name))
    _wait_role_visible(iam, role_name, timeout_s=60)
    return role_arn


def _delete_role_ignore_not_found(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _wait_role_visible(iam, role_name: str, timeout_s: float = 60.0, interval_s: float = 3.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            time.sleep(interval_s)  # brief settle for cross-service IAM propagation
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise
            time.sleep(interval_s)
    raise AssertionError(f"role {role_name} never became visible to IAM reads")


def _pipeline_name(ctx) -> str:
    raw = ctx.unique_name("sim2real-")
    slug = re.sub(r"[^a-z0-9-]", "", raw.lower())
    if not slug or not slug[0].isalpha():
        slug = "p" + slug
    return slug[:28]


def _cloudwatch_logs_body(role_arn: str, extra_processor: str = "") -> str:
    return (
        "pipeline:\n"
        "  source:\n"
        "    cloudwatch_logs:\n"
        "      log_event_metadata:\n"
        '        data_source_name: "sim2real_src"\n'
        '        data_source_type: "default"\n'
        "      aws:\n"
        f'        sts_role_arn: "{role_arn}"\n'
        "  processor:\n"
        "    - parse_json: {}\n"
        f"{extra_processor}"
        "  sink:\n"
        "    - cloudwatch_logs:\n"
        '        log_group: "@original"\n'
    )


def _wait_pipeline_terminal(client, arn: str, timeout_s: float = 150.0, interval_s: float = 5.0):
    terminal = {"ACTIVE", "CREATE_FAILED", "UPDATE_FAILED"}
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = client.get_telemetry_pipeline(PipelineIdentifier=arn)["Pipeline"]["Status"]
        if status in terminal:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"pipeline {arn} never reached a terminal status (last={status})")


def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, so a
    target that accepts a request real AWS refuses cannot pass as a plain code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _delete_pipeline_ignore_not_found(client, arn: str) -> None:
    try:
        client.delete_telemetry_pipeline(PipelineIdentifier=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("ResourceNotFoundException", "ConflictException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
