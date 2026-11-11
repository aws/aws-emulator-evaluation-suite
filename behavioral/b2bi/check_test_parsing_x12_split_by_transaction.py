"""test-parsing-x12-split-by-transaction."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "test-parsing-x12-split-by-transaction"
GROUP = "data-plane"
SERVICES = ["b2bi"]

# One interchange containing TWO X12 850 transactions under a single GS functional group.
SAMPLE_850_TWO_TRANSACTIONS = (
    "ISA*00*          *00*          *ZZ*SENDER         *ZZ*RECEIVER       *230101*1200*U*00401*000000001*0*P*>~\n"
    "GS*PO*SENDER*RECEIVER*20230101*1200*1*X*004010~\n"
    "ST*850*0001~\n"
    "BEG*00*SA*PO000001**20230101~\n"
    "N1*ST*FIRST CORP~\n"
    "PO1*1*10*EA*25.00**BP*ITEM001*VN*ITEM-A~\n"
    "SE*4*0001~\n"
    "ST*850*0002~\n"
    "BEG*00*SA*PO000002**20230101~\n"
    "N1*ST*SECOND CORP~\n"
    "PO1*1*20*EA*30.00**BP*ITEM002*VN*ITEM-B~\n"
    "SE*4*0002~\n"
    "GE*2*1~\n"
    "IEA*1*000000001~\n"
)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestParsing's X12 split-by-TRANSACTION option genuinely splits a multi-transaction
    interchange into one parsedSplitFileContents entry per transaction, each carrying only
    that transaction's own business data (not the whole interchange repeated)."""
    b2bi = ctx.client("b2bi")
    bucket = _create_bucket(ctx)
    key = "two-transaction-850.edi"
    ctx.client("s3").put_object(Bucket=bucket, Key=key, Body=SAMPLE_850_TWO_TRANSACTIONS.encode("utf-8"))

    resp = b2bi.test_parsing(
        ediType={"x12Details": {"transactionSet": "X12_850", "version": "VERSION_4010"}},
        fileFormat="JSON",
        inputFile={"bucketName": bucket, "key": key},
        advancedOptions={"x12": {"splitOptions": {"splitBy": "TRANSACTION"}}},
    )
    splits = resp.get("parsedSplitFileContents") or []
    assert len(splits) == 2, f"expected exactly 2 split transactions, got {len(splits)}: {splits!r}"

    joined = "".join(splits)
    assert "PO000001" in joined and "PO000002" in joined, f"expected both PO numbers, got: {splits!r}"

    # Each split part must contain only its OWN transaction's data, not both.
    first_has_second = "PO000002" in splits[0]
    second_has_first = "PO000001" in splits[1]
    assert not (first_has_second and second_has_first), (
        "each split part should carry only its own transaction's PO number, not both -- "
        f"a stub that just repeats the whole file per split would fail this: {splits!r}"
    )


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
