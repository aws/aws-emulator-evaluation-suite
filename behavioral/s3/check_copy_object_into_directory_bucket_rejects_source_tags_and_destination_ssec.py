"""copy-object-into-directory-bucket-rejects-source-tags-and-destination-ssec."""
from __future__ import annotations

import base64
import hashlib
import os

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "copy-object-into-directory-bucket-rejects-source-tags-and-destination-ssec"
GROUP = "directory-bucket-copy-restrictions"
SERVICES = ["s3"]

# S3 Express One Zone Availability-Zone IDs per region. Zone IDs (not names) are physical and
# identical in every account, so this table holds for any account.
_S3EXPRESS_AZ_IDS = {
    "us-east-1": ["use1-az4", "use1-az5", "use1-az6"],
    "us-east-2": ["use2-az1", "use2-az2"],
    "us-west-2": ["usw2-az1", "usw2-az3", "usw2-az4"],
    "ap-south-1": ["aps1-az1", "aps1-az3"],
    "ap-northeast-1": ["apne1-az1", "apne1-az4"],
    "eu-central-1": ["euc1-az1", "euc1-az2"],
    "eu-west-1": ["euw1-az1", "euw1-az3"],
    "eu-north-1": ["eun1-az1", "eun1-az2", "eun1-az3"],
}


def _empty_and_delete_bucket(s3, bucket):
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        for obj in page.get("Contents", []) or []:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _directory_bucket(ctx, s3, prefix):
    """Create an S3 Express directory bucket, registering its teardown in the same breath."""
    azs = _S3EXPRESS_AZ_IDS.get(ctx.region)
    if not azs:
        raise AssertionError(f"S3 Express One Zone AZ IDs not known for region {ctx.region!r}")
    base = ctx.unique_name(prefix)
    last = None
    for az in azs:
        name = f"{base}--{az}--x-s3"
        try:
            s3.create_bucket(
                Bucket=name,
                CreateBucketConfiguration={
                    "Location": {"Type": "AvailabilityZone", "Name": az},
                    "Bucket": {"DataRedundancy": "SingleAvailabilityZone", "Type": "Directory"},
                },
            )
        except ClientError as exc:
            last = exc
            continue
        ctx.on_cleanup(lambda b=name: _empty_and_delete_bucket(s3, b))
        return name
    raise AssertionError(f"could not create a directory bucket in any of {azs!r}: {last}")


def _general_purpose_bucket(ctx, s3, prefix):
    name = ctx.unique_name(prefix)
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CopyObject into a directory bucket refuses a tagged source copied with TaggingDirective=COPY
    and a destination requesting SSE-C, both with their exact errors; an untagged, unencrypted
    source still copies in."""
    s3 = ctx.client("s3")
    directory = _directory_bucket(ctx, s3, "sim2real-s3x-copy-")
    source = _general_purpose_bucket(ctx, s3, "sim2real-s3x-copy-src-")

    s3.put_object(Bucket=source, Key="tagged.txt", Body=b"tagged-bytes", Tagging="class=gold")
    code, message = _error(lambda: s3.copy_object(
        Bucket=directory, Key="copy-tagged.txt", CopySource={"Bucket": source, "Key": "tagged.txt"}))
    assert (code, message) == (
        "NotImplemented", "This bucket does not support copying source objects with Object Tags."
    ), f"CopyObject of a tagged source (TaggingDirective=COPY) into a directory bucket returned {(code, message)!r}"

    s3.put_object(Bucket=source, Key="plain.txt", Body=b"plain-bytes")
    key_bytes = os.urandom(32)
    key_b64 = base64.b64encode(key_bytes).decode()
    key_md5 = base64.b64encode(hashlib.md5(key_bytes).digest()).decode()
    code, message = _error(lambda: s3.copy_object(
        Bucket=directory, Key="copy-ssec.txt", CopySource={"Bucket": source, "Key": "plain.txt"},
        SSECustomerAlgorithm="AES256", SSECustomerKey=key_b64, SSECustomerKeyMD5=key_md5))
    assert (code, message) == (
        "NotImplemented", "This bucket does not support server side encryption with a customer provided key."
    ), f"CopyObject requesting destination SSE-C on a directory bucket returned {(code, message)!r}"

    for refused in ("copy-tagged.txt", "copy-ssec.txt"):
        absent = _error(lambda k=refused: s3.head_object(Bucket=directory, Key=k))
        assert absent[0] == "404", f"the refused copy to {refused!r} must create no object, got {absent!r}"

    # Positive control: the same source bucket, an untagged and unencrypted object, copies in fine.
    copied = s3.copy_object(Bucket=directory, Key="copy-plain.txt", CopySource={"Bucket": source, "Key": "plain.txt"})
    assert copied["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"the untagged, unencrypted control copy returned HTTP "
        f"{copied['ResponseMetadata']['HTTPStatusCode']!r}, expected 200"
    )
    body = s3.get_object(Bucket=directory, Key="copy-plain.txt")["Body"].read()
    assert body == b"plain-bytes", f"the control copy holds {body!r}, want b'plain-bytes'"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
