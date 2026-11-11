"""test-parsing-x12-850-purchase-order."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "test-parsing-x12-850-purchase-order"
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

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=bucket, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestParsing of an X12 850 purchase order in S3 returns parsed output containing the
    document's BEG03 purchase order reference."""
    b2bi = ctx.client("b2bi")
    s3 = ctx.client("s3")
    bucket = _create_bucket_for_b2bi(ctx)
    key = "in/sample-850.edi"
    s3.put_object(Bucket=bucket, Key=key, Body=_SAMPLE_850_EDI.encode("utf-8"))

    resp = b2bi.test_parsing(
        ediType={"x12Details": {"transactionSet": "X12_850", "version": "VERSION_4010"}},
        fileFormat="JSON",
        inputFile={"bucketName": bucket, "key": key},
    )

    parsed = resp["parsedFileContent"]
    assert parsed, "expected non-empty parsedFileContent for a valid X12 850 document"

    # TEST123 also appears in the raw EDI input, so the output must be JSON without the raw
    # segment framing and carry TEST123 as a discrete field value.
    try:
        parsed_obj = json.loads(parsed)
    except json.JSONDecodeError as exc:
        raise AssertionError(
            "fileFormat=JSON was requested but parsedFileContent is not valid JSON "
            f"(looks like an echo of the raw input rather than a parse): {parsed[:200]!r}"
        ) from exc

    assert "~" not in parsed and "ISA*" not in parsed, (
        "parsedFileContent still contains raw X12 segment terminators/qualifiers -- "
        f"looks like an echo of the input rather than a parse: {parsed[:200]!r}"
    )

    def _has_leaf_value(obj, target) -> bool:
        if isinstance(obj, dict):
            return any(_has_leaf_value(v, target) for v in obj.values())
        if isinstance(obj, list):
            return any(_has_leaf_value(v, target) for v in obj)
        return obj == target

    assert _has_leaf_value(parsed_obj, "TEST123"), (
        "expected the BEG03 PO reference TEST123 to appear as a discrete parsed field value "
        f"in the JSON output, got: {parsed!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
