"""start-label-detection-job-reaches-terminal-state."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "start-label-detection-job-reaches-terminal-state"
GROUP = "data-plane"
SERVICES = ["rekognition"]


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartLabelDetection on a real stored video drives VideoJobStatus IN_PROGRESS -> a terminal state with real labels."""
    video_bytes, extension = _fetch_sample_video_bytes()
    s3 = ctx.client("s3")
    rek = ctx.client("rekognition")
    bucket = ctx.unique_name("sim2real-rek-video-").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)
    key = f"sample.{extension}"
    s3.put_object(Bucket=bucket, Key=key, Body=video_bytes)

    job_id = rek.start_label_detection(Video={"S3Object": {"Bucket": bucket, "Name": key}})["JobId"]

    final = _poll_until(
        lambda: rek.get_label_detection(JobId=job_id, MaxResults=10),
        lambda resp: resp["JobStatus"] in ("SUCCEEDED", "FAILED"),
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert final["JobStatus"] == "SUCCEEDED", final.get("StatusMessage")
    labels = final.get("Labels", [])
    assert len(labels) > 0, f"expected at least one detected label, got {labels!r}"


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=10.0):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


#: A 3 s, 10 fps H.264 MP4 of the shipped face photograph (deployments/face.jpg, CC0), made with
#: ffmpeg so no run fetches media.
_SAMPLE_VIDEO = "face.mp4"


def _fetch_sample_video_bytes():
    from pathlib import Path

    return (Path(__file__).parent / "deployments" / _SAMPLE_VIDEO).read_bytes(), "mp4"


def _create_bucket(ctx, s3, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objects = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objects:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objects})
    s3.delete_bucket(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
