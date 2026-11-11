"""codebuild-buildspec-finally-block-runs-after-a-failing-command-and-its-output-is-uploaded."""
from __future__ import annotations

import json
import time


from botocore.exceptions import ClientError

from behavioral_harness import tags

# ===== helpers =====

_SCENARIO = "codebuild-finally-block"
_IMAGE = "aws/codebuild/standard:7.0"


def _delete_role(iam, role_name):
    """Delete an IAM role after its inline policies; NoSuchEntity means it is already gone."""
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_service_role(ctx, statements):
    """Mint a real CodeBuild-assumable service role carrying exactly `statements`."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-codebuild-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "codebuild.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
    )
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="codebuild-inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    # IAM propagation has no condition to poll; _create_project retries through it.
    return resp["Role"]["Arn"]


def _create_bucket(s3, bucket_name, region):
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(Bucket=bucket_name,
                         CreateBucketConfiguration={"LocationConstraint": region})


def _empty_and_delete_bucket(s3, bucket_name):
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket_name):
            objects = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objects:
                s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objects})
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _list_keys(s3, bucket, prefix=""):
    """Every key under `prefix`, across all pages."""
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return sorted(keys)


def _create_project(cb, ctx, name, role_arn, buildspec, **over):
    """CreateProject on NO_SOURCE + an inline buildspec, retrying through IAM trust-policy
    propagation; registers teardown immediately on success. Returns the project dict."""
    args = {
        "name": name,
        "source": {"type": "NO_SOURCE", "buildspec": buildspec},
        "artifacts": {"type": "NO_ARTIFACTS"},
        "cache": {"type": "NO_CACHE"},
        "environment": {"type": "LINUX_CONTAINER", "image": _IMAGE,
                        "computeType": "BUILD_GENERAL1_SMALL"},
        "serviceRole": role_arn,
        "logsConfig": {"cloudWatchLogs": {"status": "DISABLED"},
                       "s3Logs": {"status": "DISABLED"}},
        "timeoutInMinutes": 5,
        "tags": [{"key": "sim2real", "value": _SCENARIO}],
    }
    args.update(over)
    deadline = time.monotonic() + 120
    while True:
        try:
            proj = cb.create_project(**args)["project"]
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            msg = (err.get("Message") or "").lower()
            transient_role = err.get("Code") == "InvalidInputException" and (
                "assume" in msg or "not authorized" in msg)
            if transient_role and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: cb.delete_project(name=proj["name"]))
    return proj


def _stop(cb, build_id):
    try:
        cb.stop_build(id=build_id)
    except ClientError as exc:
        # The build is already terminal (InvalidInputException) or gone: nothing left to stop.
        if exc.response["Error"]["Code"] not in ("InvalidInputException", "ResourceNotFoundException"):
            raise


def _start_build_with_stop_registered(cb, ctx, **kwargs):
    """Register the StopBuild cleanup BEFORE issuing StartBuild, so a build that starts and
    then trips an assertion still gets stopped instead of billing its whole timeout."""
    holder = {"id": None}
    ctx.on_cleanup(lambda: holder["id"] and _stop(cb, holder["id"]))
    resp = cb.start_build(**kwargs)
    holder["id"] = resp["build"]["id"]
    return resp["build"]


def _poll_build_terminal(cb, build_id, *, timeout_s, interval_s=3.0):
    """Poll BatchGetBuilds until buildComplete, bounded by a deadline. Returns the terminal
    Build dict, or None if the deadline passed while it was still running."""
    deadline = time.monotonic() + timeout_s
    while True:
        got = cb.batch_get_builds(ids=[build_id])
        builds = got.get("builds", [])
        assert builds, f"BatchGetBuilds lost build {build_id!r}: {got!r}"
        last = builds[0]
        if last.get("buildComplete") is True:
            return last
        if time.monotonic() >= deadline:
            return None
        time.sleep(interval_s)


def _phases(build):
    return [(p.get("phaseType"), p.get("phaseStatus")) for p in build.get("phases", [])]

# ===== check =====

CHECK = "codebuild-buildspec-finally-block-runs-after-a-failing-command-and-its-output-is-uploaded"
GROUP = 'buildspec-semantics'
SERVICES = ['codebuild', 's3']


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """After a build command exits 7, the phase's finally block still runs after it and the FAILED
    build still uploads its artifact, which carries both markers in order.

    Reference: https://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html
    """
    cb = ctx.client("codebuild")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-cb-fin-").lower().replace("_", "-")
    _create_bucket(s3, bucket, ctx.region)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    role = _create_service_role(ctx, [
        {"Effect": "Allow",
         "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
         "Resource": "*"},
        {"Effect": "Allow",
         "Action": ["s3:PutObject", "s3:GetObject", "s3:GetBucketAcl",
                    "s3:GetBucketLocation", "s3:ListBucket"],
         "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"]},
    ])

    buildspec = (
        "version: 0.2\n"
        "phases:\n"
        "  build:\n"
        "    commands:\n"
        "      - echo sim2real-pre-marker >> out.txt\n"
        "      - exit 7\n"
        "    finally:\n"
        "      - echo sim2real-finally-marker >> out.txt\n"
        "artifacts:\n"
        "  files:\n"
        "    - out.txt\n"
    )

    name = ctx.unique_name("sim2real-behav-proj-fin-")
    _create_project(
        cb, ctx, name, role, buildspec,
        artifacts={"type": "S3", "location": bucket, "path": "out", "name": "build",
                   "namespaceType": "NONE", "packaging": "NONE",
                   "encryptionDisabled": True},
    )

    started = _start_build_with_stop_registered(cb, ctx, projectName=name)
    build = _poll_build_terminal(cb, started["id"], timeout_s=240)
    assert build is not None, f"build {started['id']!r} never reported buildComplete"

    assert build["buildStatus"] == "FAILED", (
        f"expected FAILED after a command exiting 7, got {build['buildStatus']!r}; "
        f"phases={_phases(build)!r}"
    )
    by_type = {p.get("phaseType"): p for p in build.get("phases", [])}
    build_phase = by_type.get("BUILD")
    assert build_phase is not None and build_phase.get("phaseStatus") == "FAILED", (
        f"the BUILD phase must be the one that failed, phases were {_phases(build)!r}"
    )
    build_context = " ".join(
        (c.get("message") or "") for c in (build_phase.get("contexts") or []))
    assert "7" in build_context, (
        f"the BUILD phase context did not carry the command's exit status 7: "
        f"{build_context!r}"
    )

    keys = _list_keys(s3, bucket)
    assert len(keys) == 1, (
        f"a FAILED build whose finally block wrote the declared artifact should still leave "
        f"exactly one object, bucket holds {keys!r}"
    )
    artifact = s3.get_object(Bucket=bucket, Key=keys[0])["Body"].read()
    assert b"sim2real-pre-marker" in artifact, (
        f"the command that ran before the failure left nothing in the artifact: "
        f"{artifact[:160]!r}"
    )
    assert b"sim2real-finally-marker" in artifact, (
        f"the finally block did not run after the failing command: {artifact[:160]!r}"
    )
    assert artifact.index(b"sim2real-pre-marker") < artifact.index(
            b"sim2real-finally-marker"), (
        f"the finally block ran BEFORE the failing command: {artifact[:200]!r}"
    )
    location = build.get("artifacts", {}).get("location") or ""
    assert location.endswith(f"{bucket}/out/build"), (
        f"a FAILED build must still report where it uploaded its artifact, reported "
        f"{location!r} while the object is at {bucket}/{keys[0]}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
