"""start-key-phrases-detection-job-reaches-completed."""
from __future__ import annotations

import io
import json
import tarfile
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-key-phrases-detection-job-reaches-completed"
GROUP = "state-machine"
SERVICES = ["comprehend"]

_DOC_TEXT = b"Bob lives in Seattle. He is a software engineer at Amazon.\n"


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A key-phrases job on a tiny document moves SUBMITTED -> IN_PROGRESS -> COMPLETED and writes
    S3 output whose KeyPhrases name the nouns of the input document."""
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    input_key = "input/doc.txt"
    s3.put_object(Bucket=bucket, Key=input_key, Body=_DOC_TEXT)
    role_arn = _create_job_role(ctx, bucket)
    comprehend = ctx.client("comprehend")

    def _start():
        return comprehend.start_key_phrases_detection_job(
            LanguageCode="en",
            DataAccessRoleArn=role_arn,
            InputDataConfig={
                "S3Uri": f"s3://{bucket}/{input_key}",
                "InputFormat": "ONE_DOC_PER_LINE",
            },
            OutputDataConfig={"S3Uri": f"s3://{bucket}/output/"},
        )

    final = _run_job_to_completion(ctx, comprehend, _start)

    output_uri = final["OutputDataConfig"]["S3Uri"]
    prefix = f"s3://{bucket}/"
    assert output_uri.startswith(prefix), output_uri
    output_key = output_uri[len(prefix):]
    body = s3.get_object(Bucket=bucket, Key=output_key)["Body"].read()
    assert len(body) > 0, "job output object is empty"

    result = _first_json_record_from_output(body)
    phrases = {kp["Text"].lower() for kp in result["KeyPhrases"]}
    assert phrases, f"job output carries no KeyPhrases: {result!r}"
    expected_substrings = ("seattle", "software engineer", "amazon")
    matched = [sub for sub in expected_substrings if any(sub in phrase for phrase in phrases)]
    assert matched, (
        f"none of {expected_substrings} were detected as key phrases in {_DOC_TEXT!r}, "
        f"got {phrases!r}"
    )


# ===== helpers =====
def _run_job_to_completion(ctx, comprehend, start_fn, max_attempts=4):
    """IAM role/policy propagation is eventually consistent: comprehend can accept a freshly
    created role for StartKeyPhrasesDetectionJob (sts:AssumeRole already visible) and then fail
    the job itself moments later with NO_WRITE_ACCESS_TO_OUTPUT / NO_READ_ACCESS_TO_INPUT because
    the S3 permissions on that same role have not propagated yet. Retry the whole
    start-and-poll cycle -- bounded, with a pause for propagation -- rather than trusting the
    first job's verdict."""
    last = None
    for attempt in range(1, max_attempts + 1):
        job_id = _start_job_with_retry(start_fn)["JobId"]

        def _probe():
            return comprehend.describe_key_phrases_detection_job(JobId=job_id)[
                "KeyPhrasesDetectionJobProperties"
            ]

        last = _poll_until(
            _probe,
            lambda p: p["JobStatus"] in ("COMPLETED", "FAILED", "STOPPED"),
            timeout_s=1800.0,
            interval_s=20.0,
        )
        if last["JobStatus"] == "COMPLETED":
            return last
        message = last.get("Message") or ""
        if attempt < max_attempts and (
            "NO_WRITE_ACCESS_TO_OUTPUT" in message or "NO_READ_ACCESS_TO_INPUT" in message
        ):
            time.sleep(2)
            continue
        break
    raise AssertionError(
        f"job ended in {last['JobStatus']} after {attempt} attempt(s): {last.get('Message')}"
    )


def _first_json_record_from_output(raw_bytes):
    try:
        with tarfile.open(fileobj=io.BytesIO(raw_bytes), mode="r:gz") as tar:
            for member in tar.getmembers():
                if not member.isfile():
                    continue
                extracted = tar.extractfile(member)
                if extracted is None:
                    continue
                for line in extracted.read().decode("utf-8").splitlines():
                    line = line.strip()
                    if line:
                        return json.loads(line)
    except tarfile.ReadError:
        import gzip

        for line in gzip.decompress(raw_bytes).decode("utf-8").splitlines():
            line = line.strip()
            if line:
                return json.loads(line)
    raise AssertionError("job output carried no JSON result lines")


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-comprehend-").lower().replace("_", "-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name):
    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _create_job_role(ctx, bucket):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-comprehend-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "comprehend.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": f"arn:aws:s3:::{bucket}/*"},
            {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": f"arn:aws:s3:::{bucket}"},
            {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": f"arn:aws:s3:::{bucket}/*"},
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="comprehend-job-access", PolicyDocument=json.dumps(policy_doc))
    return role_arn


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName="comprehend-job-access")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _start_job_with_retry(fn, timeout_s=120.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "").lower()
            if code in ("AccessDeniedException", "InvalidRequestException") and (
                "role" in message or "assume" in message or "permission" in message
            ):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc if last_exc is not None else RuntimeError("job start retry timed out")


def _poll_until(probe, predicate, timeout_s, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
