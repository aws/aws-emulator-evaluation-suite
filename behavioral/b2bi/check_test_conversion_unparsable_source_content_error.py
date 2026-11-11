"""test-conversion-unparsable-source-content-error."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "test-conversion-unparsable-source-content-error"
GROUP = "overly-permissive"
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


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestConversion rejects source content declared JSON that is not valid JSON with
    ValidationException and no output, while a well-formed document from TestParsing converts."""
    b2bi = ctx.client("b2bi")

    code, message = _error(
        lambda: b2bi.test_conversion(
            source={"fileFormat": "JSON", "inputFile": {"fileContent": "{ this is not valid json ((("}},
            target={
                "fileFormat": "X12",
                "formatDetails": {"x12": {"transactionSet": "X12_850", "version": "VERSION_4010"}},
            },
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = (
        "Unexpected character ('t' (code 116)): was expecting double-quote to start field name at "
        "[Source: REDACTED (`StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION` disabled); line: 1, column: 3]"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: a real, well-formed source obtained from an actual TestParsing call
    # (so it is guaranteed to match the service's canonical shape) converts cleanly.
    bucket = _create_bucket(ctx)
    key = "sample-850.edi"
    ctx.client("s3").put_object(Bucket=bucket, Key=key, Body=SAMPLE_850_EDI.encode("utf-8"))
    parsed = b2bi.test_parsing(
        ediType={"x12Details": {"transactionSet": "X12_850", "version": "VERSION_4010"}},
        fileFormat="JSON",
        inputFile={"bucketName": bucket, "key": key},
    )["parsedFileContent"]

    ok = b2bi.test_conversion(
        source={"fileFormat": "JSON", "inputFile": {"fileContent": parsed}},
        target={
            "fileFormat": "X12",
            "formatDetails": {"x12": {"transactionSet": "X12_850", "version": "VERSION_4010"}},
        },
    )
    converted = ok["convertedFileContent"]
    assert "PO123456" in converted, (
        f"expected the PO number to survive conversion of real test-parsing output, got: {converted[:500]!r}"
    )


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
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "b2bi-test-conversion"}]})

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
