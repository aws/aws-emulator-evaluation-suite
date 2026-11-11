"""telemetry-pipeline-create-active-transition."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "telemetry-pipeline-create-active-transition"
GROUP = "state"
SERVICES = ["observabilityadmin"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A pipeline whose source role trusts logs.amazonaws.com but has no permission policies goes from
    CREATING to ACTIVE (CreateTelemetryPipeline checks the role exists and is passable, not what it may
    do); after delete, GetTelemetryPipeline fails with ResourceNotFoundException "Pipeline not found"."""
    client = ctx.client("observabilityadmin")
    name = _pipeline_name(ctx)
    role_arn = _create_permissionless_source_role(ctx)
    body = _cloudwatch_logs_pipeline_body(role_arn=role_arn)

    created = _create_telemetry_pipeline_debug(client, name, body)
    arn = created["Arn"]
    ctx.on_cleanup(lambda: _delete_pipeline_ignore_not_found(client, arn))

    status = _wait_pipeline_terminal(client, arn, timeout_s=150)
    assert status == "ACTIVE", f"expected ACTIVE for an existing-but-permissionless source role, got {status!r}"
    pipeline = client.get_telemetry_pipeline(PipelineIdentifier=arn)["Pipeline"]
    assert pipeline["Status"] == "ACTIVE", (
        f"a fresh GetTelemetryPipeline must agree with the polled status, got {pipeline['Status']!r}"
    )

    client.delete_telemetry_pipeline(PipelineIdentifier=arn)

    def _get():
        client.get_telemetry_pipeline(PipelineIdentifier=arn)

    code, message = _wait_for_error_code(_get, "ResourceNotFoundException", timeout_s=90)
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {code!r}"
    assert message == "Pipeline not found", f"ResourceNotFoundException message {message!r}"


def _create_telemetry_pipeline_debug(client, name, body):
    try:
        return client.create_telemetry_pipeline(Name=name, Configuration={"Body": body})
    except ClientError as e:
        raise AssertionError(f"CreateTelemetryPipeline failed: {e.response!r}") from e


def _create_permissionless_source_role(ctx) -> str:
    # A role that actually EXISTS (so CreateTelemetryPipeline's own role-existence/PassRole
    # checks succeed) and trusts the CloudWatch Logs service principal (matching the
    # cloudwatch_logs source use case), but that has zero permissions policies attached -- so
    # the pipeline cannot actually read from the source once it starts running, and is
    # expected to land in CREATE_FAILED rather than ACTIVE.
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
    created_role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)
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


def _cloudwatch_logs_pipeline_body(role_arn: str, extra_processor: str = "") -> str:
    processor = "    - parse_json: {}\n" + extra_processor
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
        f"{processor}"
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


def _wait_for_error_code(fn, expected_code: str, timeout_s: float = 90.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            fn()
            last = None
        except ClientError as e:
            last = e.response["Error"]["Code"]
            if last == expected_code:
                return last, e.response["Error"]["Message"]
        time.sleep(interval_s)
    raise AssertionError(f"expected error {expected_code!r}, got {last!r} after {timeout_s}s")


def _delete_pipeline_ignore_not_found(client, arn: str) -> None:
    try:
        client.delete_telemetry_pipeline(PipelineIdentifier=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("ResourceNotFoundException", "ConflictException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
