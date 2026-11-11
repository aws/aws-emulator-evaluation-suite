"""create-starter-mapping-template-with-output-sample."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags

CHECK = "create-starter-mapping-template-with-output-sample"
GROUP = "data-plane"
SERVICES = ["b2bi"]

# outputSampleLocation must be a sample EDI document (the desired output of a JSON/XML -> EDI
# conversion); AWS rejects a JSON body there with "The EDI file could not be parsed."
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


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateStarterMappingTemplate carries the outputSampleLocation document's envelope and field
    values into the template, and TestMapping running that template reproduces those values."""
    b2bi = ctx.client("b2bi")
    bucket = _create_bucket(ctx)
    key = "samples/sample-850-output.edi"
    ctx.client("s3").put_object(Bucket=bucket, Key=key, Body=SAMPLE_850_EDI.encode("utf-8"))

    resp = b2bi.create_starter_mapping_template(
        mappingType="JSONATA",
        templateDetails={"x12": {"transactionSet": "X12_850", "version": "VERSION_4010"}},
        outputSampleLocation={"bucketName": bucket, "key": key},
    )
    template = resp["mappingTemplate"]
    assert isinstance(template, str) and len(template) > 0, "expected a non-empty starter template"
    _assert_template_derived_from_sample(json.loads(template))

    applied = b2bi.test_mapping(fileFormat="JSON", inputFileContent="{}", mappingTemplate=template)
    assert "mappedFileContent" in applied, f"expected TestMapping to return mappedFileContent, got {applied!r}"
    # mappedFileContent is a JSON string literal wrapping the mapped JSON document, hence the double parse.
    mapped = json.loads(json.loads(applied["mappedFileContent"]))
    _assert_template_derived_from_sample(mapped)


def _assert_template_derived_from_sample(doc: dict) -> None:
    """Both the starter template and TestMapping's output are the same canonicalized EDI-as-JSON
    shape; assert both the verbatim envelope values and the placeholder-ized business values that
    only a read of the sample produces."""
    interchange = doc["interchanges"][0]
    assert interchange["ISA_06_SenderId"].strip() == "SENDER", (
        f"expected the ISA sender id from the sample echoed verbatim, got {interchange['ISA_06_SenderId']!r}"
    )
    assert interchange["ISA_13_InterchangeControlNumber"] == "000000001", (
        "expected the ISA interchange control number from the sample echoed verbatim, got "
        f"{interchange['ISA_13_InterchangeControlNumber']!r}"
    )
    transaction = interchange["functional_groups"][0]["transactions"][0]
    beg_segment = next(seg for seg in transaction["segments"] if "BEG_03" in seg)
    assert beg_segment["BEG_03"] == "PLACEHOLDER: PO123456", (
        f"expected the PO number from the sample surfaced as a placeholder, got {beg_segment['BEG_03']!r}"
    )
    po1_loop = next(seg for seg in transaction["segments"] if "PO1-8000_loop" in seg)["PO1-8000_loop"][0]
    assert po1_loop["PO1_09"] == "PLACEHOLDER: WIDGET-A", (
        f"expected the line item id from the sample surfaced as a placeholder, got {po1_loop['PO1_09']!r}"
    )


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-b2bi-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real-created-with", "Value": CHECK}]},
    )

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

