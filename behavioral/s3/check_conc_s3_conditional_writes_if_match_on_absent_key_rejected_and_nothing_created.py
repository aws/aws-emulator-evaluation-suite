"""conc-s3-conditional-writes-if-match-on-absent-key-rejected-and-nothing-created."""

from __future__ import annotations

import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "conc-s3-conditional-writes-if-match-on-absent-key-rejected-and-nothing-created"
GROUP = 'conditional-rejection'
SERVICES = ['s3']

_NO_SUCH_KEY_MSG = 'The specified key does not exist.'


def _delete_bucket(s3, bucket):
    """Abort uploads, empty every version and marker, then delete the bucket (raises if it cannot)."""
    try:
        for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
            for u in page.get("Uploads", []):
                s3.abort_multipart_upload(Bucket=bucket, Key=u["Key"], UploadId=u["UploadId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                s3.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3):
    name = ctx.unique_name("sim2real-condw-")
    params = {"Bucket": name}
    # us-east-1 is the one region CreateBucket rejects a LocationConstraint for; not a region pin.
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _abort_upload(s3, bucket, key, upload_id):
    try:
        s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchUpload":
            raise


def _client_error(fn, refused="the call succeeded; AWS refuses it with a ClientError"):
    """Call fn(); return the ClientError it raised. A call that succeeds fails the check."""
    try:
        fn()
    except ClientError as exc:
        return exc
    raise AssertionError(refused)


def _message(exc):
    return exc.response.get("Error", {}).get("Message")


def _listed(s3, bucket):
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys += [o["Key"] for o in page.get("Contents", [])]
    return sorted(keys)


def _md5_etag(body):
    return '"' + hashlib.md5(body).hexdigest() + '"'


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """If-Match on an absent key is refused 404 NoSuchKey on PutObject and CompleteMultipartUpload
    and creates nothing; once the key exists, If-Match with its current ETag succeeds.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "cas/absent.txt"
    mpu_key = "cas/absent-multipart.bin"
    body = b"compare-and-swap-must-not-create-a-missing-key"

    # The offered ETag is the body's own MD5, so only the key's absence can fail the request.
    exc = _client_error(lambda: s3.put_object(Bucket=bucket, Key=key, Body=body,
                                              IfMatch=_md5_etag(body)),
                        "PutObject If-Match on an absent key SUCCEEDED; the guard is being read as "
                        "'no condition' and the key was created")
    code = exc.response.get("Error", {}).get("Code")
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert code == "NoSuchKey", f"expected NoSuchKey for If-Match on an absent key, got {code!r}"
    assert _message(exc) == _NO_SUCH_KEY_MSG, (
        f"expected message {_NO_SUCH_KEY_MSG!r}, got {_message(exc)!r}"
    )
    assert status == 404, f"expected HTTP 404, got {status!r}"

    # --- Same boundary, CompleteMultipartUpload path.
    upload_id = s3.create_multipart_upload(Bucket=bucket, Key=mpu_key)["UploadId"]
    ctx.on_cleanup(lambda: _abort_upload(s3, bucket, mpu_key, upload_id))
    part_etag = s3.upload_part(Bucket=bucket, Key=mpu_key, UploadId=upload_id, PartNumber=1,
                               Body=body)["ETag"]
    mpu_exc = _client_error(lambda: s3.complete_multipart_upload(
        Bucket=bucket, Key=mpu_key, UploadId=upload_id,
        MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": part_etag}]}, IfMatch=part_etag,
    ), "CompleteMultipartUpload If-Match on an absent key SUCCEEDED and created the object")
    mpu_code = mpu_exc.response.get("Error", {}).get("Code")
    mpu_status = mpu_exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert mpu_code == "NoSuchKey", f"expected NoSuchKey on the multipart path, got {mpu_code!r}"
    assert _message(mpu_exc) == _NO_SUCH_KEY_MSG, (
        f"expected message {_NO_SUCH_KEY_MSG!r} on the multipart path, got {_message(mpu_exc)!r}"
    )
    assert mpu_status == 404, f"expected HTTP 404 on the multipart path, got {mpu_status!r}"

    # --- Effect absent: neither key exists, by listing and by direct read.
    assert _listed(s3, bucket) == [], (
        f"after two refused If-Match writes the bucket lists {_listed(s3, bucket)!r}; want []"
    )
    gone = _client_error(lambda: s3.get_object(Bucket=bucket, Key=key),
                         "GetObject on the refused key succeeded; the refused write created it")
    assert gone.response["Error"]["Code"] == "NoSuchKey", (
        f"GetObject on the refused key did not report NoSuchKey: {gone!r}"
    )
    assert gone.response["Error"]["Message"] == "The specified key does not exist.", (
        f'expected the exact NoSuchKey message AWS returns, got {gone.response["Error"]["Message"]!r}'
    )
    assert _message(gone) == _NO_SUCH_KEY_MSG, (
        f"expected message {_NO_SUCH_KEY_MSG!r} from GetObject, got {_message(gone)!r}"
    )

    # --- POSITIVE CONTROL: once the key exists, If-Match with its CURRENT ETag succeeds.
    first = b"now-the-key-exists"
    current = s3.put_object(Bucket=bucket, Key=key, Body=first)["ETag"]
    updated = s3.put_object(Bucket=bucket, Key=key, Body=body, IfMatch=current)
    assert updated["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"If-Match with the current ETag returned {updated['ResponseMetadata']['HTTPStatusCode']!r}"
    )
    got = s3.get_object(Bucket=bucket, Key=key)
    assert got["Body"].read() == body, "the If-Match update with the current ETag did not land"
    assert got["ETag"] == updated["ETag"] == _md5_etag(body), (
        f"GET ETag {got['ETag']!r}, PUT ETag {updated['ETag']!r}, MD5 {_md5_etag(body)!r}: "
        "want all three equal"
    )
    assert _listed(s3, bucket) == [key], (
        f"the bucket lists {_listed(s3, bucket)!r}; want exactly [{key!r}]"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
