"""index-creation-time-after-bucket-and-stable-across-reads."""

from __future__ import annotations

import datetime

from behavioral_harness import tags

CHECK = "index-creation-time-after-bucket-and-stable-across-reads"
GROUP = "index"
SERVICES = ["s3vectors"]


def _find_bucket(buckets, name):
    for b in buckets:
        if b["vectorBucketName"] == name:
            return b
    raise AssertionError(f"{name!r} missing from ListVectorBuckets: {[b['vectorBucketName'] for b in buckets]!r}")


def _find_index(indexes, name):
    for i in indexes:
        if i["indexName"] == name:
            return i
    raise AssertionError(f"{name!r} missing from ListIndexes: {[i['indexName'] for i in indexes]!r}")


def _list_all_buckets(s3v):
    pages = s3v.get_paginator("list_vector_buckets").paginate()
    return [b for page in pages for b in page["vectorBuckets"]]


def _list_all_indexes(s3v, bucket):
    pages = s3v.get_paginator("list_indexes").paginate(vectorBucketName=bucket)
    return [i for page in pages for i in page["indexes"]]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Bucket and index creationTime are server timestamps taken at creation: each
    falls in its call's wall-clock window, the index's is not before its bucket's,
    and Get/List report the identical value across repeated reads.
    """
    s3v = ctx.client("s3vectors")
    skew = datetime.timedelta(minutes=5)

    bucket = ctx.unique_name("sim2real-behav-vb-")
    before_bucket = datetime.datetime.now(datetime.timezone.utc)
    s3v.create_vector_bucket(vectorBucketName=bucket)
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket))
    after_bucket = datetime.datetime.now(datetime.timezone.utc)

    index = ctx.unique_name("sim2real-behav-idx-")
    before_index = datetime.datetime.now(datetime.timezone.utc)
    s3v.create_index(
        vectorBucketName=bucket, indexName=index, dimension=3,
        distanceMetric="cosine", dataType="float32",
    )
    ctx.on_cleanup(lambda: s3v.delete_index(vectorBucketName=bucket, indexName=index))
    after_index = datetime.datetime.now(datetime.timezone.utc)

    bucket_ct_get_1 = s3v.get_vector_bucket(vectorBucketName=bucket)["vectorBucket"]["creationTime"]
    assert before_bucket - skew <= bucket_ct_get_1 <= after_bucket + skew, (
        f"bucket creationTime {bucket_ct_get_1!r} outside call window "
        f"[{before_bucket!r}, {after_bucket!r}]"
    )

    bucket_ct_list_1 = _find_bucket(_list_all_buckets(s3v), bucket)["creationTime"]
    assert bucket_ct_list_1 == bucket_ct_get_1, (
        f"ListVectorBuckets creationTime {bucket_ct_list_1!r} != "
        f"GetVectorBucket creationTime {bucket_ct_get_1!r}"
    )

    index_ct_get_1 = s3v.get_index(vectorBucketName=bucket, indexName=index)["index"]["creationTime"]
    assert before_index - skew <= index_ct_get_1 <= after_index + skew, (
        f"index creationTime {index_ct_get_1!r} outside call window "
        f"[{before_index!r}, {after_index!r}]"
    )

    index_ct_list_1 = _find_index(_list_all_indexes(s3v, bucket), index)["creationTime"]
    assert index_ct_list_1 == index_ct_get_1, (
        f"ListIndexes creationTime {index_ct_list_1!r} != GetIndex creationTime {index_ct_get_1!r}"
    )

    assert index_ct_get_1 >= bucket_ct_get_1, (
        f"index creationTime {index_ct_get_1!r} precedes its bucket's {bucket_ct_get_1!r}"
    )

    bucket_ct_get_2 = s3v.get_vector_bucket(vectorBucketName=bucket)["vectorBucket"]["creationTime"]
    assert bucket_ct_get_2 == bucket_ct_get_1, (
        f"GetVectorBucket creationTime changed across reads: {bucket_ct_get_1!r} then {bucket_ct_get_2!r}"
    )

    bucket_ct_list_2 = _find_bucket(_list_all_buckets(s3v), bucket)["creationTime"]
    assert bucket_ct_list_2 == bucket_ct_get_1, (
        f"ListVectorBuckets creationTime changed across reads: {bucket_ct_get_1!r} then {bucket_ct_list_2!r}"
    )

    index_ct_get_2 = s3v.get_index(vectorBucketName=bucket, indexName=index)["index"]["creationTime"]
    assert index_ct_get_2 == index_ct_get_1, (
        f"GetIndex creationTime changed across reads: {index_ct_get_1!r} then {index_ct_get_2!r}"
    )

    index_ct_list_2 = _find_index(_list_all_indexes(s3v, bucket), index)["creationTime"]
    assert index_ct_list_2 == index_ct_get_1, (
        f"ListIndexes creationTime changed across reads: {index_ct_get_1!r} then {index_ct_list_2!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
