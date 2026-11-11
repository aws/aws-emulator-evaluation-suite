"""validate-pipeline-missing-permission-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "validate-pipeline-missing-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["osis"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ValidatePipeline through a new IAM role with no permissions fails with AccessDeniedException and the exact
    implicit-deny message, while the same call with the caller's own credentials returns isValid true.
    """
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-osis-noperm-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "validate-pipeline-missing-permission-rejected"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_best_effort(ctx, role_name))

    restricted_osis = _assume_role_client(ctx, role_arn)

    config = _valid_config()
    default_resp = ctx.client("osis").validate_pipeline(PipelineConfigurationBody=config)
    assert default_resp["isValid"] is True, (
        f"positive control: the harness's own credentials must validate a config known-good "
        f"elsewhere in this suite; got isValid={default_resp.get('isValid')!r}"
    )

    error = _client_error(lambda: restricted_osis.validate_pipeline(PipelineConfigurationBody=config))
    assert error.get("Code") == "AccessDeniedException", (
        f"expected AccessDeniedException, got {error.get('Code')!r}"
    )
    expected = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/{_SESSION_NAME} is not "
        f"authorized to perform: osis:ValidatePipeline on resource: "
        f"arn:aws:osis:{ctx.region}:{ctx.account}:* because no identity-based policy allows the "
        f"osis:ValidatePipeline action"
    )
    assert error.get("Message") == expected, f"expected message {expected!r}, got {error.get('Message')!r}"


def _valid_config() -> str:
    # "region"/"sts_role_arn" here are fictitious pipeline-config content for schema validity
    # only -- ValidatePipeline never provisions the sink, so no client region is pinned.
    return """version: "2"
osis-behav-pipeline:
  source:
    http:
      path: "/ingest"
  sink:
    - s3:
        bucket: "placeholder-bucket-name"
        codec:
          ndjson:
        aws:
          sts_role_arn: "arn:aws:iam::123456789012:role/placeholder-pipeline-role"
          region: "us-east-1"
        threshold:
          event_count: 1
          maximum_size: "1mb"
          event_collect_timeout: "60s"
"""


_SESSION_NAME = "sim2real-osis-noperm"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"expected AccessDeniedException, but the restricted-role call SUCCEEDED and returned "
        f"{result!r}"
    )


def _assume_role_client(ctx, role_arn: str, timeout_s: float = 60):
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    creds = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(
                RoleArn=role_arn, RoleSessionName=_SESSION_NAME
            )["Credentials"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("AccessDenied", "InvalidClientTokenId"):
                time.sleep(5)
                continue
            raise
    assert creds is not None, "could not assume the freshly-created role within timeout"
    return ctx.client(
        "osis",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _delete_role_best_effort(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
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
