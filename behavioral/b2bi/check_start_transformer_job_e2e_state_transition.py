"""start-transformer-job-e2e-state-transition."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "start-transformer-job-e2e-state-transition"
GROUP = "data-plane"
SERVICES = ["b2bi"]

# Real X12 850 purchase order sample, as published in the AWS B2BI user guide tutorials
# (https://docs.aws.amazon.com/b2bi/latest/userguide/inbound-tutorial-step3-transformer.html).
_SAMPLE_850_EDI = (
    "ISA*00*          *00*          *ZZ*SUPPLIER       *ZZ*ACMECORP       *230101*1200*U*00401*000000001*0*P*>~\n"
    "GS*PO*SUPPLIER*ACMECORP*20230101*1200*1*X*004010~\n"
    "ST*850*0001~\n"
    "BEG*00*SA*TEST123**20230101~\n"
    "N1*ST*ACME CORPORATION~\n"
    "N3*456 TEST AVENUE~\n"
    "N4*TESTCITY*CA*90210*US~\n"
    "PO1*1*5*EA*15.50**BP*TEST001*VN*TEST-WIDGET~\n"
    "PID*F****TEST PREMIUM WIDGET~\n"
    "SE*8*0001~\n"
    "GE*1*1~\n"
    "IEA*1*000000001~\n"
)


def _create_bucket_for_b2bi(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-b2bi-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowB2BIAccess",
                "Effect": "Allow",
                "Principal": {"Service": "b2bi.amazonaws.com"},
                "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]}
    )

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=bucket, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed value: {last!r}")


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartTransformerJob runs a transformer on an X12 850 document in S3: the job reaches
    succeeded and its S3 output contains the transformed business data."""
    b2bi = ctx.client("b2bi")
    s3 = ctx.client("s3")
    bucket = _create_bucket_for_b2bi(ctx)

    input_key = "in/sample-850.edi"
    output_prefix = "out/"
    s3.put_object(Bucket=bucket, Key=input_key, Body=_SAMPLE_850_EDI.encode("utf-8"))

    transformer_name = ctx.unique_name("sim2real-b2bi-tr-")
    transformer = b2bi.create_transformer(
        name=transformer_name,
        inputConversion={
            "fromFormat": "X12",
            "formatOptions": {"x12": {"transactionSet": "X12_850", "version": "VERSION_4010"}},
        },
        mapping={"templateLanguage": "JSONATA", "template": "$"},
        tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    transformer_id = transformer["transformerId"]
    ctx.on_cleanup(lambda: b2bi.delete_transformer(transformerId=transformer_id))
    # Transformers are created Inactive; StartTransformerJob requires an active one.
    b2bi.update_transformer(transformerId=transformer_id, status="active")

    started = b2bi.start_transformer_job(
        inputFile={"bucketName": bucket, "key": input_key},
        outputLocation={"bucketName": bucket, "key": output_prefix},
        transformerId=transformer_id,
    )
    job_id = started["transformerJobId"]

    final = _poll_until(
        lambda: b2bi.get_transformer_job(transformerId=transformer_id, transformerJobId=job_id),
        lambda job: job["status"] in ("succeeded", "failed"),
        timeout_s=120,
        interval_s=3,
    )
    assert final["status"] == "succeeded", (
        f"expected the transformer job to succeed, got status={final['status']!r} "
        f"message={final.get('message')!r}"
    )

    output_files = final.get("outputFiles") or []
    assert output_files, "a succeeded job must report at least one output file location"
    output_location = output_files[0]
    body = s3.get_object(Bucket=output_location["bucketName"], Key=output_location["key"])["Body"].read()
    assert body, "the transformer job's output S3 object must not be empty"
    assert b"TEST123" in body, (
        f"expected the transformed output to surface the BEG03 PO reference TEST123, got: {body!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
