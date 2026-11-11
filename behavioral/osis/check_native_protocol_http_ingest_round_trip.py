"""native-protocol-http-ingest-round-trip."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
import uuid

import botocore.auth
import botocore.awsrequest
import botocore.credentials
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "native-protocol-http-ingest-round-trip"
GROUP = "native-protocol"
SERVICES = ["osis"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """After CreatePipeline reaches ACTIVE, a SigV4-signed JSON document POSTed to the pipeline's
    HTTP ingest endpoint flows through the pipeline and lands in the configured S3 sink, so an
    ACTIVE pipeline that drops data fails this."""
    osis = ctx.client("osis")
    name = ctx.unique_name("sim2real-osis-")
    fixture = _create_pipeline_role_and_bucket(ctx)
    config = _pipeline_config(fixture["bucket"], fixture["role_arn"], ctx.region)
    _create_pipeline_with_retry(ctx, osis, name, 1, 1, config)
    ctx.on_cleanup(lambda: _delete_pipeline_best_effort(ctx, name))
    status = _wait_for_pipeline_status(ctx, name, {"ACTIVE", "CREATE_FAILED"}, timeout_s=1200)
    assert status == "ACTIVE", f"expected pipeline {name} to reach ACTIVE, got {status}"

    pipeline = osis.get_pipeline(PipelineName=name)["Pipeline"]
    ingest_urls = pipeline.get("IngestEndpointUrls") or []
    assert ingest_urls, "ACTIVE pipeline must expose an ingest endpoint URL"
    ingest_url = f"{ctx.endpoint_url(ingest_urls[0])}/ingest"

    marker = str(uuid.uuid4())
    payload = json.dumps([{"sim2real_marker": marker, "message": "hello-osis-ingest"}]).encode("utf-8")

    status_code, resp_body = _sigv4_post(ctx, ingest_url, payload)
    assert 200 <= status_code < 300, f"ingest POST failed with HTTP {status_code}: {resp_body!r}"

    found = _poll_s3_for_marker(ctx, fixture["bucket"], marker, timeout_s=300)
    assert found, f"marker {marker} sent via the ingest endpoint never appeared in the S3 sink bucket"


# ===== helpers =====

def _sigv4_post(ctx, url: str, body: bytes):
    env = ctx.subprocess_env()
    creds = botocore.credentials.Credentials(
        access_key=env["AWS_ACCESS_KEY_ID"],
        secret_key=env["AWS_SECRET_ACCESS_KEY"],
        token=env.get("AWS_SESSION_TOKEN"),
    )
    request = botocore.awsrequest.AWSRequest(
        method="POST", url=url, data=body, headers={"Content-Type": "application/json"}
    )
    botocore.auth.SigV4Auth(creds, "osis", ctx.region).add_auth(request)
    prepared = request.prepare()
    body_bytes = prepared.body if isinstance(prepared.body, bytes) else prepared.body.encode("utf-8")
    urllib_req = urllib.request.Request(
        prepared.url, data=body_bytes, headers=dict(prepared.headers), method="POST"
    )
    try:
        with urllib.request.urlopen(urllib_req, timeout=30) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _poll_s3_for_marker(ctx, bucket: str, marker: str, timeout_s: float = 300, interval_s: float = 10) -> bool:
    s3 = ctx.client("s3")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            listing = s3.list_objects_v2(Bucket=bucket)
        except ClientError:
            listing = {}
        for obj in listing.get("Contents", []):
            body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
            if marker.encode("utf-8") in body:
                return True
        time.sleep(interval_s)
    return False


def _pipeline_config(bucket: str, role_arn: str, region: str) -> str:
    return f"""version: "2"
osis-behav-pipeline:
  source:
    http:
      path: "/ingest"
  sink:
    - s3:
        bucket: "{bucket}"
        codec:
          ndjson:
        aws:
          sts_role_arn: "{role_arn}"
          region: "{region}"
        threshold:
          event_count: 1
          maximum_size: "1mb"
          event_collect_timeout: "60s"
"""


def _create_pipeline_role_and_bucket(ctx) -> dict[str, str]:
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region
    bucket_name = ctx.unique_name("sim2real-osis-behav-")
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )

    role_name = ctx.unique_name("sim2real-osis-behav-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "osis-pipelines.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _detach_and_delete_role(ctx, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="osis-behav-s3-sink",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:PutObject",
                            "s3:PutObjectAcl",
                            "s3:AbortMultipartUpload",
                            "s3:ListBucket",
                        ],
                        "Resource": [
                            f"arn:aws:s3:::{bucket_name}",
                            f"arn:aws:s3:::{bucket_name}/*",
                        ],
                    }
                ],
            }
        ),
    )
    return {"role_arn": role_arn, "bucket": bucket_name, "role_name": role_name}


def _detach_and_delete_role(ctx, role_name: str) -> None:
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


def _empty_and_delete_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket_name):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_pipeline_with_retry(
    ctx, osis, name: str, min_units: int, max_units: int, config: str, timeout_s: float = 90
) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            osis.create_pipeline(
                PipelineName=name,
                MinUnits=min_units,
                MaxUnits=max_units,
                PipelineConfigurationBody=config,
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
            )
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            # IAM role propagation: the just-created PipelineRoleArn is not yet visible to
            # osis, which reports it as ResourceNotFoundException until it is.
            if code == "ResourceNotFoundException" and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _wait_for_pipeline_status(
    ctx, name: str, target_statuses: set[str], timeout_s: float = 1200, interval_s: float = 20
) -> str:
    osis = ctx.client("osis")
    deadline = time.monotonic() + timeout_s
    last = ""
    while time.monotonic() < deadline:
        last = osis.get_pipeline(PipelineName=name)["Pipeline"]["Status"]
        if last in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"pipeline {name} did not reach {target_statuses} within {timeout_s}s (last={last})")


def _delete_pipeline_best_effort(ctx, name: str) -> None:
    osis = ctx.client("osis")
    try:
        _wait_for_pipeline_status(
            ctx,
            name,
            {"ACTIVE", "STOPPED", "CREATE_FAILED", "UPDATE_FAILED", "START_FAILED"},
            timeout_s=720,
            interval_s=2,
        )
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    # DeletePipeline answers ConflictException while a transition settles: retry it, raise the rest.
    deadline = time.monotonic() + 150
    while True:
        try:
            osis.delete_pipeline(PipelineName=name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code == "ConflictException" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
