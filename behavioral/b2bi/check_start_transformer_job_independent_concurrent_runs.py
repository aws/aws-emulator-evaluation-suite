"""start-transformer-job-independent-concurrent-runs."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "start-transformer-job-independent-concurrent-runs"
GROUP = "data-plane"
SERVICES = ["b2bi"]

SAMPLE_850_EDI = (
    "ISA*00*          *00*          *ZZ*SENDER         *ZZ*RECEIVER       *230101*1200*U*00401*000000001*0*P*>~\n"
    "GS*PO*SENDER*RECEIVER*20230101*1200*1*X*004010~\n"
    "ST*850*0001~\n"
    "BEG*00*SA*PO123456**20230101~\n"
    "N1*ST*ACME CORPORATION~\n"
    "PO1*1*10*EA*25.00**BP*WIDGET001*VN*WIDGET-A~\n"
    "SE*5*0001~\n"
    "GE*1*1~\n"
    "IEA*1*000000001~\n"
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two StartTransformerJob calls on the same transformer and input with different output
    locations get distinct job ids, each succeeds, and each writes its own output."""
    b2bi = ctx.client("b2bi")
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)
    key = "input/sample-850.edi"
    s3.put_object(Bucket=bucket, Key=key, Body=SAMPLE_850_EDI.encode("utf-8"))
    transformer_id = _create_transformer(ctx)

    job_1 = b2bi.start_transformer_job(
        inputFile={"bucketName": bucket, "key": key},
        outputLocation={"bucketName": bucket, "key": "out-1/"},
        transformerId=transformer_id,
    )
    job_2 = _start_job_with_retry(
        b2bi,
        inputFile={"bucketName": bucket, "key": key},
        outputLocation={"bucketName": bucket, "key": "out-2/"},
        transformerId=transformer_id,
    )
    assert job_1["transformerJobId"] != job_2["transformerJobId"], "each StartTransformerJob call must mint a new job id"

    status_1 = _poll_status(ctx, transformer_id, job_1["transformerJobId"], timeout_s=120.0)
    status_2 = _poll_status(ctx, transformer_id, job_2["transformerJobId"], timeout_s=120.0)
    assert status_1 == "succeeded" and status_2 == "succeeded", (status_1, status_2)

    listing_1 = s3.list_objects_v2(Bucket=bucket, Prefix="out-1/").get("KeyCount", 0)
    listing_2 = s3.list_objects_v2(Bucket=bucket, Prefix="out-2/").get("KeyCount", 0)
    assert listing_1 >= 1 and listing_2 >= 1, "each job must have written its own output"


def _start_job_with_retry(b2bi: Any, timeout_s: float = 30.0, **kwargs: Any) -> dict:
    """StartTransformerJob against a transformer with another job already in flight can
    answer ConflictException('...previous request that is still being processed') for a
    short window while the first job's registration settles; retry until it clears."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return b2bi.start_transformer_job(**kwargs)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(2.0)


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-b2bi-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "start-transformer-job-independent-concurrent-runs"}]})

    def _cleanup():
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_transformer(ctx: Any) -> str:
    b2bi = ctx.client("b2bi")
    resp = b2bi.create_transformer(
        name=ctx.unique_name("sim2real-b2bi-xfmr-"),
        inputConversion={
            "fromFormat": "X12",
            "formatOptions": {"x12": {"transactionSet": "X12_850", "version": "VERSION_4010"}},
        },
        mapping={"templateLanguage": "JSONATA", "template": "$"},
        tags=[{"Key": "sim2real", "Value": "start-transformer-job-independent-concurrent-runs"}],
    )
    transformer_id = resp["transformerId"]
    ctx.on_cleanup(lambda: b2bi.delete_transformer(transformerId=transformer_id))
    # Transformers are created Inactive; StartTransformerJob requires an active one.
    b2bi.update_transformer(transformerId=transformer_id, status="active")
    return transformer_id


def _poll_status(ctx: Any, transformer_id: str, job_id: str, timeout_s: float = 120.0) -> str:
    b2bi = ctx.client("b2bi")
    deadline = time.monotonic() + timeout_s
    status = "running"
    while time.monotonic() < deadline:
        status = b2bi.get_transformer_job(transformerJobId=job_id, transformerId=transformer_id)["status"]
        if status != "running":
            return status
        time.sleep(3.0)
    raise TimeoutError(f"transformer job {job_id} still 'running' after {timeout_s}s, never reached a terminal status")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
