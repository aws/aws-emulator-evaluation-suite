"""get-transformer-job-cross-transformer-isolation-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "get-transformer-job-cross-transformer-isolation-rejected"
GROUP = "error-semantics"
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


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetTransformerJob with a job id and another transformer's id returns
    ResourceNotFoundException; the same job is found with its own transformerId."""
    b2bi = ctx.client("b2bi")
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)
    key = "input/sample-850.edi"
    s3.put_object(Bucket=bucket, Key=key, Body=SAMPLE_850_EDI.encode("utf-8"))

    owner_transformer = _create_transformer(ctx)
    other_transformer = _create_transformer(ctx)

    job = b2bi.start_transformer_job(
        inputFile={"bucketName": bucket, "key": key},
        outputLocation={"bucketName": bucket, "key": "out/"},
        transformerId=owner_transformer,
    )
    job_id = job["transformerJobId"]
    _poll_terminal(ctx, owner_transformer, job_id, timeout_s=120.0)

    code, message = _error(
        lambda: b2bi.get_transformer_job(transformerJobId=job_id, transformerId=other_transformer)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"Found no transformer job {job_id} for customer {ctx.account}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: the same job, looked up under its real owning transformer, is found.
    owned = b2bi.get_transformer_job(transformerJobId=job_id, transformerId=owner_transformer)
    assert owned["status"] == "succeeded", f"expected the job to still be found under its owning transformer, got status {owned['status']!r}"


def _error(fn) -> tuple[str, str]:
    """Call fn(), which AWS refuses; return the ClientError's (code, message). An unexpected
    success raises, so accepting a request AWS refuses fails the check."""
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


def _create_transformer(ctx: Any) -> str:
    b2bi = ctx.client("b2bi")
    resp = b2bi.create_transformer(
        name=ctx.unique_name("sim2real-b2bi-xfmr-"),
        inputConversion={
            "fromFormat": "X12",
            "formatOptions": {"x12": {"transactionSet": "X12_850", "version": "VERSION_4010"}},
        },
        mapping={"templateLanguage": "JSONATA", "template": "$"},
        tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    transformer_id = resp["transformerId"]
    ctx.on_cleanup(lambda: b2bi.delete_transformer(transformerId=transformer_id))
    # Transformers are created Inactive; StartTransformerJob requires an active one.
    b2bi.update_transformer(transformerId=transformer_id, status="active")
    return transformer_id


def _poll_terminal(ctx: Any, transformer_id: str, job_id: str, timeout_s: float = 120.0) -> str:
    b2bi = ctx.client("b2bi")
    deadline = time.monotonic() + timeout_s
    status = "running"
    while time.monotonic() < deadline:
        status = b2bi.get_transformer_job(transformerJobId=job_id, transformerId=transformer_id)["status"]
        if status != "running":
            break
        time.sleep(3.0)
    assert status == "succeeded", f"expected job to succeed before testing isolation, got {status!r}"
    return status


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
