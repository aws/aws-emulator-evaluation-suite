"""start-speech-synthesis-task-invalid-s3-bucket-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-speech-synthesis-task-invalid-s3-bucket-rejected"
GROUP = "overly-permissive"
SERVICES = ["polly"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartSpeechSynthesisTask rejects an OutputS3BucketName that violates the bucket-name pattern
    with ValidationException and creates no task, while a well-formed but nonexistent bucket
    still gets a task targeting it and a real bucket gets a task writing to it."""
    polly = ctx.client("polly")
    pattern_violating_bucket = "UPPERCASE_NOT_ALLOWED"

    # independent read, taken before the rejected call, to prove absence below
    ids_before_reject = {t["TaskId"] for t in _list_all(polly)}

    code, message = _error_code(
        lambda: polly.start_speech_synthesis_task(
            OutputFormat="mp3",
            OutputS3BucketName=pattern_violating_bucket,
            Text="This bucket name violates the OutputS3BucketName pattern.",
            VoiceId="Joanna",
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException, got {code!r}"
    )
    expected_message = (
        f"1 validation error detected: Value '{pattern_violating_bucket}' at 'outputS3BucketName' "
        "failed to satisfy constraint: Member must satisfy regular expression pattern: "
        r"^[a-z0-9][\.\-a-z0-9]{1,61}[a-z0-9]$"
    )
    assert message == expected_message, message

    # effect absent: the rejected request created no task, via an independent
    # read (ListSpeechSynthesisTasks) rather than inferred from the missing TaskId
    ids_after_reject = {t["TaskId"] for t in _list_all(polly)}
    assert ids_after_reject == ids_before_reject, (
        f"rejected request must not create a task: before={ids_before_reject} "
        f"after={ids_after_reject}"
    )

    # boundary: a well-formed but nonexistent bucket is NOT rejected synchronously
    nonexistent_bucket = ctx.unique_name("sim2real-polly-missing-").lower().replace("_", "-")
    started_missing = polly.start_speech_synthesis_task(
        OutputFormat="mp3",
        OutputS3BucketName=nonexistent_bucket,
        Text="This bucket does not exist but the name is well-formed.",
        VoiceId="Joanna",
    )["SynthesisTask"]
    assert started_missing["TaskId"] not in ids_before_reject, (
        f"missing-bucket task id {started_missing['TaskId']!r} collided with a prior task"
    )

    # independent read: GetSpeechSynthesisTask (a different operation than the
    # one that created it) confirms the task exists at the destination targeting
    # the nonexistent bucket, even though it is not rejected synchronously
    fetched_missing = polly.get_speech_synthesis_task(
        TaskId=started_missing["TaskId"]
    )["SynthesisTask"]
    assert fetched_missing["TaskId"] == started_missing["TaskId"], fetched_missing
    assert nonexistent_bucket in (fetched_missing.get("OutputUri") or ""), (
        f"expected OutputUri to reference {nonexistent_bucket!r}, got {fetched_missing.get('OutputUri')!r}"
    )

    # positive control: a real bucket accepts the task
    bucket = _create_bucket(ctx)
    started = polly.start_speech_synthesis_task(
        OutputFormat="mp3",
        OutputS3BucketName=bucket,
        Text="This bucket exists.",
        VoiceId="Joanna",
    )["SynthesisTask"]
    assert started["TaskId"] not in ids_before_reject, (
        f"positive-control task id {started['TaskId']!r} collided with a prior task"
    )

    # terminal read: an independent GetSpeechSynthesisTask -- not the create
    # call's own response -- confirms the task exists at the destination and
    # is progressing against the real bucket
    fetched = polly.get_speech_synthesis_task(TaskId=started["TaskId"])["SynthesisTask"]
    assert fetched["TaskId"] == started["TaskId"], fetched
    assert bucket in (fetched.get("OutputUri") or ""), (
        f"expected OutputUri to reference {bucket!r}, got {fetched.get('OutputUri')!r}"
    )
    assert fetched["TaskStatus"] in ("scheduled", "inProgress", "completed"), (
        f"unexpected TaskStatus {fetched['TaskStatus']!r} for {fetched['TaskId']!r}"
    )


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-polly-badbucket-").lower().replace("_", "-")
    kwargs: dict[str, Any] = {"Bucket": name}
    # us-east-1 is the only region where CreateBucket rejects an explicit
    # LocationConstraint; every other region requires one matching ctx.region
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [
            {"Key": "sim2real", "Value": "start-speech-synthesis-task-invalid-s3-bucket-rejected"}
        ]},
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    return name


def _empty_and_delete_bucket(s3, name: str) -> None:
    try:
        objs = s3.list_objects_v2(Bucket=name).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _list_all(polly):
    out = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = polly.list_speech_synthesis_tasks(**kwargs)
        out.extend(resp["SynthesisTasks"])
        token = resp.get("NextToken")
        if not token:
            return out


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
