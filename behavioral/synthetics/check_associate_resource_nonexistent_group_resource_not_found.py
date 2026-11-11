"""associate-resource-nonexistent-group-resource-not-found."""
from __future__ import annotations

import json
import time
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-resource-nonexistent-group-resource-not-found"
GROUP = "error-semantics"
SERVICES = ["synthetics"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateResource against a nonexistent group returns ResourceNotFoundException."""
    synth = ctx.client("synthetics")
    account = ctx.client("sts").get_caller_identity()["Account"]
    fake_canary_arn = f"arn:aws:synthetics:{ctx.region}:{account}:canary:sim2real-never-created"
    missing_group = ctx.unique_name("sim2real-nogroup-")

    error = _client_error(lambda: synth.associate_resource(GroupIdentifier=missing_group, ResourceArn=fake_canary_arn))
    assert error["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {error!r}"
    expected_message = f"Group does not exist: {missing_group}"
    assert error["Message"] == expected_message, f"expected message {expected_message!r}, got {error['Message']!r}"

    # Positive control: associating a real canary ARN with a real group succeeds.
    group_name = ctx.unique_name("sim2real-group-")
    synth.create_group(Name=group_name, Tags={"sim2real": "audit"})

    def _cleanup_group() -> None:
        try:
            synth.delete_group(GroupIdentifier=group_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_group)

    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_execution_role(ctx, bucket)
    runtime = _latest_runtime_version(ctx)
    canary_name = ctx.unique_name("sim2real-canary-").replace("_", "-")
    _create_canary_with_retry(ctx, name=canary_name, bucket=bucket, role_arn=role_arn, runtime=runtime,
                               schedule_expr="rate(1 hour)")
    ctx.on_cleanup(lambda: _cleanup_canary(ctx, canary_name))
    real_canary_arn = f"arn:aws:synthetics:{ctx.region}:{account}:canary:{canary_name}"

    synth.associate_resource(GroupIdentifier=group_name, ResourceArn=real_canary_arn)
    resources = synth.list_group_resources(GroupIdentifier=group_name)["Resources"]
    assert real_canary_arn in resources, f"expected {real_canary_arn!r} in group resources, got {resources!r}"


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
    if ctx.region != "us-east-1":  # us-east-1 is S3's API default and rejects a matching LocationConstraint
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "audit"}]})

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_execution_role(ctx, bucket_name: str, grant_permissions: bool = True) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-synth-role-")
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_iam_trust_policy(),
        Tags=[{"Key": "sim2real", "Value": "audit"}],
    )
    role_arn = role["Role"]["Arn"]
    if grant_permissions:
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


def _create_canary_with_retry(ctx, *, name, bucket, role_arn, runtime, schedule_expr,
                               code_bytes: bytes | None = None, handler: str = "canary.handler") -> dict:
    synth = ctx.client("synthetics")
    code = code_bytes if code_bytes is not None else _minimal_code_zip()
    last_exc = None
    for _ in range(10):
        try:
            return synth.create_canary(
                Name=name,
                Code={"ZipFile": code, "Handler": handler},
                ArtifactS3Location=f"s3://{bucket}",
                ExecutionRoleArn=role_arn,
                Schedule={"Expression": schedule_expr},
                RuntimeVersion=runtime,
                Tags={"sim2real": "audit"},
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
