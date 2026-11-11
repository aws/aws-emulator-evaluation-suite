"""test-parsing-malformed-edi-document-error."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "test-parsing-malformed-edi-document-error"
GROUP = "error-semantics"
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
    """TestParsing rejects a document that isn't valid X12 with ValidationException, while a
    real X12 850 document in the same bucket still parses successfully (positive control)."""
    b2bi = ctx.client("b2bi")
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")

    bad_key = "not-edi-at-all.txt"
    s3.put_object(Bucket=bucket, Key=bad_key, Body=b"this is plainly not an X12 EDI document")

    code, message = _error(
        lambda: b2bi.test_parsing(
            ediType={"x12Details": {"transactionSet": "X12_850", "version": "VERSION_4010"}},
            fileFormat="JSON",
            inputFile={"bucketName": bucket, "key": bad_key},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = "The EDI file could not be parsed. No supported EDI standard interchange begins with thi"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    good_key = "sample-850-input.edi"
    s3.put_object(Bucket=bucket, Key=good_key, Body=SAMPLE_850_EDI.encode("utf-8"))
    ok = b2bi.test_parsing(
        ediType={"x12Details": {"transactionSet": "X12_850", "version": "VERSION_4010"}},
        fileFormat="JSON",
        inputFile={"bucketName": bucket, "key": good_key},
    )
    parsed = ok["parsedFileContent"]
    assert "PO123456" in parsed, (
        f"expected the parsed output to surface the BEG03 PO reference PO123456, got: {parsed!r}"
    )


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
