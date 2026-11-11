"""list-telemetry-pipelines-pagination."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-telemetry-pipelines-pagination"
GROUP = "data-plane"
SERVICES = ["observabilityadmin"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTelemetryPipelines honors MaxResults=1 (returns exactly one summary per page and
    a NextToken while more remain) and paginating through NextToken eventually surfaces every
    pipeline created in this account, not just the first page."""
    client = ctx.client("observabilityadmin")
    role_arn = _create_source_role(ctx)
    created_names = []
    created_arns = []
    for _ in range(3):
        name = _pipeline_name(ctx)
        data_source_name = ctx.unique_name("sim2real_src_")
        body = _cloudwatch_logs_body(role_arn, data_source_name)
        created = client.create_telemetry_pipeline(
            Name=name, Configuration={"Body": body}, Tags={"sim2real": CHECK}
        )
        arn = created["Arn"]
        created_names.append(name)
        created_arns.append(arn)
        ctx.on_cleanup(lambda a=arn: _delete_pipeline_ignore_not_found(client, a))

    first_page = client.list_telemetry_pipelines(MaxResults=1)
    assert len(first_page["PipelineSummaries"]) == 1, (
        f"expected exactly 1 summary with MaxResults=1, got {len(first_page['PipelineSummaries'])}"
    )
    assert first_page.get("NextToken"), "expected a NextToken while more pipelines remain, got none"

    all_names = set()
    next_token = None
    for _ in range(200):  # bounded pagination walk
        params = {"MaxResults": 1}
        if next_token:
            params["NextToken"] = next_token
        page = client.list_telemetry_pipelines(**params)
        all_names.update(s["Name"] for s in page["PipelineSummaries"])
        next_token = page.get("NextToken")
        if not next_token:
            break

    for name in created_names:
        assert name in all_names, f"expected {name!r} to surface via pagination, saw {all_names!r}"


def _create_source_role(ctx) -> str:
    # A role that actually EXISTS and trusts the CloudWatch Logs service principal, so
    # CreateTelemetryPipeline's role validation succeeds. Permissions don't matter for this
    # check (it only exercises pagination), so none are attached.
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


def _cloudwatch_logs_body(role_arn: str, data_source_name: str) -> str:
    return (
        "pipeline:\n"
        "  source:\n"
        "    cloudwatch_logs:\n"
        "      log_event_metadata:\n"
        f'        data_source_name: "{data_source_name}"\n'
        '        data_source_type: "default"\n'
        "      aws:\n"
        f'        sts_role_arn: "{role_arn}"\n'
        "  processor:\n"
        "    - parse_json: {}\n"
        "  sink:\n"
        "    - cloudwatch_logs:\n"
        '        log_group: "@original"\n'
    )


def _delete_pipeline_ignore_not_found(client, arn: str) -> None:
    try:
        client.delete_telemetry_pipeline(PipelineIdentifier=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("ResourceNotFoundException", "ConflictException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
