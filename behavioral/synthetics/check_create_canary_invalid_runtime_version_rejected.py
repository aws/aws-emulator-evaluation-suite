"""create-canary-invalid-runtime-version-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-canary-invalid-runtime-version-rejected"
GROUP = "overly-permissive"
SERVICES = ["synthetics"]


@tags("axis:rejection", "cap:c1", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCanary rejects an unknown RuntimeVersion with ValidationException and leaves no
    canary behind; the same request with a real runtime version succeeds."""
    synth = ctx.client("synthetics")
    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_execution_role(ctx, bucket)
    bad_name = ctx.unique_name("sim2real-canary-").replace("_", "-")

    bad_runtime = "syn-nodejs-puppeteer-not-a-real-version"
    error = _client_error(lambda: synth.create_canary(
        Name=bad_name,
        Code={"ZipFile": _minimal_code_zip(), "Handler": "canary.handler"},
        ArtifactS3Location=f"s3://{bucket}",
        ExecutionRoleArn=role_arn,
        Schedule={"Expression": "rate(1 hour)"},
        RuntimeVersion=bad_runtime,
    ))
    assert error["Code"] == "ValidationException", f"expected ValidationException, got {error!r}"
    expected_message = f"Invalid runtime version specified: {bad_runtime}"
    assert error["Message"] == expected_message, f"expected message {expected_message!r}, got {error['Message']!r}"

    # Effect absent: no canary was created under that name.
    names = [c["Name"] for c in synth.describe_canaries(Names=[bad_name]).get("Canaries", [])]
    assert bad_name not in names, "a canary was created despite the invalid RuntimeVersion"

    # Positive control: the same request with a real runtime version succeeds.
    good_name = ctx.unique_name("sim2real-canary-").replace("_", "-")
    runtime = _latest_runtime_version(ctx)
    _create_canary_with_retry(ctx, name=good_name, bucket=bucket, role_arn=role_arn, runtime=runtime,
                               schedule_expr="rate(1 hour)")
    ctx.on_cleanup(lambda: _cleanup_canary(ctx, good_name))
    names_good = [c["Name"] for c in synth.describe_canaries(Names=[good_name]).get("Canaries", [])]
    assert good_name in names_good, f"expected {good_name!r} in describe_canaries, got {names_good!r}"


# ===== helpers =====

def _client_error(fn) -> dict:
    """Call fn() and return the botocore Error dict (Code, Message). An unexpected SUCCESS
    raises its own AssertionError, so an accepted call that AWS refuses is reported as an
    unexpected success rather than as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _iam_trust_policy() -> str:
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-synth-").lower().replace("_", "-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_execution_role(ctx, bucket_name: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-synth-role-")
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_iam_trust_policy(),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    statements = [
        {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], "Resource": "*"},
        {"Effect": "Allow", "Action": ["s3:PutObject", "s3:GetBucketLocation"],
         "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"]},
        {"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"},
        {"Effect": "Allow", "Action": "cloudwatch:PutMetricData", "Resource": "*",
         "Condition": {"StringEquals": {"cloudwatch:namespace": "CloudWatchSynthetics"}}},
    ]
    iam.put_role_policy(
        RoleName=role_name, PolicyName="synthetics-exec",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )

    def _cleanup() -> None:
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="synthetics-exec")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _minimal_code_zip() -> bytes:
    import zipfile
    from io import BytesIO
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("nodejs/node_modules/canary.js", "exports.handler = async () => { return 'ok'; };\n")
    return buf.getvalue()


def _latest_runtime_version(ctx, prefix: str = "syn-nodejs-puppeteer-") -> str:
    synth = ctx.client("synthetics")
    candidates = []
    token = None
    while True:
        kwargs = {"MaxResults": 20}
        if token:
            kwargs["NextToken"] = token
        resp = synth.describe_runtime_versions(**kwargs)
        for rv in resp["RuntimeVersions"]:
            if rv["VersionName"].startswith(prefix) and not rv.get("DeprecationDate"):
                candidates.append(rv["VersionName"])
        token = resp.get("NextToken")
        if not token:
            break
    if not candidates:
        raise AssertionError(f"no non-deprecated runtime version found for prefix {prefix}")
    return candidates[-1]


def _create_canary_with_retry(ctx, *, name, bucket, role_arn, runtime, schedule_expr) -> dict:
    synth = ctx.client("synthetics")
    code = _minimal_code_zip()
    last_exc = None
    for _ in range(10):
        try:
            return synth.create_canary(
                Name=name,
                Code={"ZipFile": code, "Handler": "canary.handler"},
                ArtifactS3Location=f"s3://{bucket}",
                ExecutionRoleArn=role_arn,
                Schedule={"Expression": schedule_expr},
                RuntimeVersion=runtime,
            )
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] in ("ValidationException", "AccessDeniedException"):
                time.sleep(3)
                continue
            raise
    raise AssertionError(f"create_canary never succeeded (IAM propagation?): {last_exc}")


def _cleanup_canary(ctx, name: str) -> None:
    """Stop the canary if it runs, then delete it once it settles; a missing canary is clean.
    ConflictException (a transition still in flight) is retried every 2 s to a deadline."""
    synth = ctx.client("synthetics")
    deadline = time.monotonic() + 300
    stop_sent = False
    state = None
    while True:
        try:
            state = synth.get_canary(Name=name)["Canary"]["Status"]["State"]
            if state == "RUNNING" and not stop_sent:
                synth.stop_canary(Name=name)
                stop_sent = True
            elif state not in ("STOPPING", "RUNNING", "STARTING", "UPDATING", "CREATING", "DELETING"):
                synth.delete_canary(Name=name, DeleteLambda=True)
                return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"canary {name} still {state} at the cleanup deadline; not deleted")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
