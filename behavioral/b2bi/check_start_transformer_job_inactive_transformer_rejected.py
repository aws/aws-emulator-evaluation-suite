"""start-transformer-job-inactive-transformer-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "start-transformer-job-inactive-transformer-rejected"
GROUP = "overly-permissive"
SERVICES = ["b2bi"]

SAMPLE_850_EDI = (
    "ISA*00*          *00*          *ZZ*SENDER         *ZZ*RECEIVER       *230101*1200*U*00401*000000001*0*P*>~\n"
    "GS*PO*SENDER*RECEIVER*20230101*1200*1*X*004010~\n"
    "ST*850*0001~\n"
    "BEG*00*SA*PO123456**20230101~\n"
    "N1*ST*ACME CORPORATION~\n"
    "N3*123 MAIN STREET~\n"
    "N4*ANYTOWN*NY*12345*US~\n"
    "PO1*1*10*EA*25.00**BP*WIDGET001*VN*WIDGET-A~\n"
    "PID*F****PREMIUM WIDGET~\n"
    "SE*8*0001~\n"
    "GE*1*1~\n"
    "IEA*1*000000001~\n"
)


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartTransformerJob rejects an inactive transformer with ValidationException and never
    creates a job for it, while an active transformer in the same file still runs to completion."""
    b2bi = ctx.client("b2bi")
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)
    input_key = "input/sample-850-input.edi"
    s3.put_object(Bucket=bucket, Key=input_key, Body=SAMPLE_850_EDI.encode("utf-8"))

    def _make_transformer():
        xfmr = b2bi.create_transformer(
            name=ctx.unique_name("sim2real-b2bi-xfmr-"),
            inputConversion={
                "fromFormat": "X12",
                "formatOptions": {"x12": {"transactionSet": "X12_850", "version": "VERSION_4010"}},
            },
            mapping={"templateLanguage": "JSONATA", "template": "$"},
            tags=[{"Key": "sim2real-created-with", "Value": "start-transformer-job-inactive-transformer-rejected"}],
        )
        tid = xfmr["transformerId"]
        ctx.on_cleanup(lambda: b2bi.delete_transformer(transformerId=tid))
        assert xfmr["status"] == "inactive", f"expected a freshly created transformer to be inactive, got {xfmr['status']!r}"
        return tid

    inactive_id = _make_transformer()
    assert b2bi.get_transformer(transformerId=inactive_id)["status"] == "inactive"

    code, message = _error(
        lambda: b2bi.start_transformer_job(
            inputFile={"bucketName": bucket, "key": input_key},
            outputLocation={"bucketName": bucket, "key": "out-inactive/"},
            transformerId=inactive_id,
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = f"Transformer {inactive_id} must be active"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: nothing was written under the output prefix for the rejected job.
    listing = s3.list_objects_v2(Bucket=bucket, Prefix="out-inactive/")
    assert listing.get("KeyCount", 0) == 0, "rejected job must not have written any output"

    # Positive control: an active transformer with the identical input still runs successfully.
    active_id = _make_transformer()
    b2bi.update_transformer(transformerId=active_id, status="active")
    job = b2bi.start_transformer_job(
        inputFile={"bucketName": bucket, "key": input_key},
        outputLocation={"bucketName": bucket, "key": "out-active/"},
        transformerId=active_id,
    )
    status = _poll_status(ctx, active_id, job["transformerJobId"], timeout_s=120.0)
    assert status == "succeeded", f"expected the active transformer's job to succeed, got {status!r}"


def _error(fn) -> tuple[str, str]:
    """Call fn(), which AWS refuses; return the ClientError's (code, message). An unexpected
    success raises, so a target that accepts the call fails loudly instead of mismatching."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-b2bi-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup():
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _poll_status(ctx: Any, transformer_id: str, job_id: str, timeout_s: float = 120.0) -> str:
    b2bi = ctx.client("b2bi")
    deadline = time.monotonic() + timeout_s
    status = "running"
    while time.monotonic() < deadline:
        status = b2bi.get_transformer_job(transformerJobId=job_id, transformerId=transformer_id)["status"]
        if status != "running":
            return status
        time.sleep(3.0)
    raise AssertionError(
        f"transformer job {job_id!r} did not leave status=running within {timeout_s}s"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
