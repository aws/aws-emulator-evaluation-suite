"""test-conversion-json-to-x12-roundtrip."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "test-conversion-json-to-x12-roundtrip"
GROUP = "data-plane"
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


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A real X12 850 document, parsed to the service's canonical JSON shape and then converted
    back with TestConversion, must round-trip the business data (PO number, transaction set)."""
    b2bi = ctx.client("b2bi")
    bucket = _create_bucket(ctx)
    key = "sample-850-input.edi"
    ctx.client("s3").put_object(Bucket=bucket, Key=key, Body=SAMPLE_850_EDI.encode("utf-8"))

    parsed = b2bi.test_parsing(
        ediType={"x12Details": {"transactionSet": "X12_850", "version": "VERSION_4010"}},
        fileFormat="JSON",
        inputFile={"bucketName": bucket, "key": key},
    )["parsedFileContent"]

    converted = b2bi.test_conversion(
        source={"fileFormat": "JSON", "inputFile": {"fileContent": parsed}},
        target={
            "fileFormat": "X12",
            "formatDetails": {"x12": {"transactionSet": "X12_850", "version": "VERSION_4010"}},
        },
    )
    edi_out = converted["convertedFileContent"]
    assert "ST*850" in edi_out, f"expected an X12 850 transaction segment, got: {edi_out[:500]!r}"
    assert "PO123456" in edi_out, f"expected the PO number to survive the round trip, got: {edi_out[:500]!r}"


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-b2bi-")
    # CreateBucketConfiguration.LocationConstraint must be omitted for us-east-1 specifically —
    # passing it there is rejected as an invalid location constraint.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

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
