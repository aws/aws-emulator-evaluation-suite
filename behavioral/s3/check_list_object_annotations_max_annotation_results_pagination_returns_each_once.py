"""list-object-annotations-max-annotation-results-pagination-returns-each-once."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-object-annotations-max-annotation-results-pagination-returns-each-once"
GROUP = "object-annotation"
SERVICES = ["s3"]

_N_ANNOTATIONS = 5
_MAX_RESULTS = 2


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListObjectAnnotations with MaxAnnotationResults=2 over 5 annotations pages with a
    NextContinuationToken; following ContinuationToken returns every annotation name, size and
    ETag exactly once, and the final page carries no NextContinuationToken."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "annotated-object.bin"
    s3.put_object(Bucket=bucket, Key=key, Body=b"payload")
    ctx.on_cleanup(_teardown(lambda: s3.delete_object(Bucket=bucket, Key=key), "NoSuchKey"))

    written = {}
    for i in range(_N_ANNOTATIONS):
        name = f"pagination-annotation-{i}"
        payload = f"value-{i}".encode()
        put = s3.put_object_annotation(
            Bucket=bucket, Key=key, AnnotationName=name, AnnotationPayload=payload
        )
        written[name] = {"Size": len(payload), "ETag": put["ETag"]}

    seen: dict[str, dict] = {}
    token = None
    pages = 0
    while True:
        kwargs = {"Bucket": bucket, "Key": key, "MaxAnnotationResults": _MAX_RESULTS}
        if token is not None:
            kwargs["ContinuationToken"] = token
        resp = s3.list_object_annotations(**kwargs)
        pages += 1
        assert pages <= _N_ANNOTATIONS, (
            f"pagination did not converge after {pages} pages: seen {sorted(seen)!r}"
        )
        page_annotations = resp["Annotations"]
        assert len(page_annotations) <= _MAX_RESULTS, (
            f"page returned {len(page_annotations)} annotation(s), more than "
            f"MaxAnnotationResults={_MAX_RESULTS}: {[a['AnnotationName'] for a in page_annotations]!r}"
        )
        for a in page_annotations:
            assert a["AnnotationName"] not in seen, (
                f"annotation {a['AnnotationName']!r} was returned on more than one page"
            )
            seen[a["AnnotationName"]] = {"Size": a["Size"], "ETag": a["ETag"]}
        next_token = resp.get("NextContinuationToken")
        if next_token is None:
            break
        assert next_token != token, (
            f"NextContinuationToken did not advance past {token!r}: {resp!r}"
        )
        token = next_token

    assert set(seen) == set(written), (
        f"paginating ListObjectAnnotations with MaxAnnotationResults={_MAX_RESULTS} must return "
        f"every one of {sorted(written)!r} exactly once; got {sorted(seen)!r}"
    )
    for name, expect in written.items():
        assert seen[name] == expect, (
            f"annotation {name!r}'s paginated {{Size, ETag}} {seen[name]!r} != "
            f"PutObjectAnnotation's own {expect!r}"
        )


def _new_bucket(ctx, s3) -> str:
    """Create a uniquely-named bucket and register its teardown."""
    name = ctx.unique_name("sim2real-behav-loap-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(_teardown(lambda: s3.delete_bucket(Bucket=name), "NoSuchBucket"))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises; only not_found codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
