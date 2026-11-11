"""codebuild-artifact-upload-denied-without-s3-putobject-permission."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# ===== helpers =====

_SCENARIO = "codebuild-artifact-denied"
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
    """Mint a real CodeBuild-assumable service role carrying exactly `statements`. Returns
    (role_name, role_arn) because this check later REPAIRS one of the two roles."""
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
    # IAM propagation exposes no condition to poll; the bounded retry inside
    # _create_project (transient_role branch) is what makes this correct.
    return role_name, resp["Role"]["Arn"]


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
    """Every key under `prefix`, paginated: the pool is shared and page one is not a bound."""
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


def _phase_context(build, phase_type):
    phase = next((p for p in build.get("phases", [])
                  if p.get("phaseType") == phase_type), None)
    if phase is None:
        return None, ""
    return phase, " ".join((c.get("message") or "") for c in (phase.get("contexts") or []))


def _run_build(cb, ctx, name, marker):
    started = _start_build_with_stop_registered(
        cb, ctx, projectName=name,
        environmentVariablesOverride=[
            {"name": "SIM2REAL_MARKER", "value": marker, "type": "PLAINTEXT"}])
    final = _poll_build_terminal(cb, started["id"], timeout_s=240)
    assert final is not None, f"build {started['id']!r} never reported buildComplete"
    return final


# ===== check =====

CHECK = "codebuild-artifact-upload-denied-without-s3-putobject-permission"
GROUP = 'artifacts'
SERVICES = ['codebuild', 's3']


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A build whose role lacks s3:PutObject on its artifact bucket is refused at UPLOAD_ARTIFACTS
    and leaves no object, while a sibling role with the permission uploads in the same run and
    granting the permission makes the refused role's next build land its object."""
    cb = ctx.client("codebuild")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = ctx.unique_name("sim2real-behav-cb-deny-").lower().replace("_", "-")
    _create_bucket(s3, bucket, ctx.region)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    decoy = ctx.unique_name("sim2real-behav-cb-decoy-").lower().replace("_", "-")

    logs_stmt = {"Effect": "Allow",
                 "Action": ["logs:CreateLogGroup", "logs:CreateLogStream",
                            "logs:PutLogEvents"],
                 "Resource": "*"}

    def _s3_stmt(target):
        return {"Effect": "Allow",
                "Action": ["s3:PutObject", "s3:GetObject", "s3:GetBucketAcl",
                           "s3:GetBucketLocation", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{target}", f"arn:aws:s3:::{target}/*"]}

    # Both roles are minted BEFORE any build runs, so no propagation delta can explain the
    # difference between them - the only difference is which bucket the s3 grant names.
    _, ok_arn = _create_service_role(ctx, [logs_stmt, _s3_stmt(bucket)])
    denied_name, denied_arn = _create_service_role(ctx, [logs_stmt, _s3_stmt(decoy)])

    buildspec = (
        "version: 0.2\n"
        "phases:\n"
        "  build:\n"
        "    commands:\n"
        '      - printf \'%s\' "$SIM2REAL_MARKER" > artifact.txt\n'
        "artifacts:\n"
        "  files:\n"
        "    - artifact.txt\n"
    )
    artifacts = {"type": "S3", "location": bucket, "path": "out", "name": "build",
                 "namespaceType": "BUILD_ID", "packaging": "NONE",
                 "encryptionDisabled": True}

    ok_project = ctx.unique_name("sim2real-behav-proj-ok-")
    denied_project = ctx.unique_name("sim2real-behav-proj-deny-")
    _create_project(cb, ctx, ok_project, ok_arn, buildspec, artifacts=artifacts)
    _create_project(cb, ctx, denied_project, denied_arn, buildspec, artifacts=artifacts)

    # --- barrier: the permitted role uploads, so the whole path demonstrably works ---
    ok_marker = ctx.unique_name("sim2real-ok-")
    ok_build = _run_build(cb, ctx, ok_project, ok_marker)
    assert ok_build["buildStatus"] == "SUCCEEDED", (
        f"the permitted control build was {ok_build['buildStatus']!r}; phases="
        f"{_phases(ok_build)!r}"
    )
    ok_keys = [k for k in _list_keys(s3, bucket) if ok_build["id"].split(":")[-1] in k]
    assert len(ok_keys) == 1, (
        f"the permitted build should land exactly one object, landed {ok_keys!r}; the whole "
        f"bucket holds {_list_keys(s3, bucket)!r}"
    )
    ok_body = s3.get_object(Bucket=bucket, Key=ok_keys[0])["Body"].read()
    assert ok_body == ok_marker.encode(), (
        f"the permitted build's artifact held {ok_body[:80]!r}, expected "
        f"{ok_marker.encode()!r}"
    )

    # --- break exactly one thing: the same upload from a role without the grant -----
    deny_marker = ctx.unique_name("sim2real-deny-")
    deny_build = _run_build(cb, ctx, denied_project, deny_marker)
    assert deny_build["buildStatus"] == "FAILED", (
        f"a build whose role cannot PutObject into its artifact bucket must FAIL, got "
        f"{deny_build['buildStatus']!r}; phases={_phases(deny_build)!r}"
    )
    upload_phase, upload_context = _phase_context(deny_build, "UPLOAD_ARTIFACTS")
    assert upload_phase is not None and upload_phase.get("phaseStatus") == "FAILED", (
        f"the refusal must land in UPLOAD_ARTIFACTS, phases were {_phases(deny_build)!r}"
    )
    build_phase, _ = _phase_context(deny_build, "BUILD")
    assert build_phase is not None and build_phase.get("phaseStatus") == "SUCCEEDED", (
        f"the commands themselves must still have succeeded, so the only failure is the "
        f"upload; phases were {_phases(deny_build)!r}"
    )
    assert "denied" in upload_context.lower(), (
        f"the UPLOAD_ARTIFACTS context did not report an access denial: {upload_context!r}"
    )
    deny_keys = [k for k in _list_keys(s3, bucket) if deny_build["id"].split(":")[-1] in k]
    assert deny_keys == [], (
        f"an object landed for a build whose artifact upload was denied: {deny_keys!r}; the "
        f"whole bucket holds {_list_keys(s3, bucket)!r}"
    )

    # --- repair the one broken thing: the same project must then upload -------------
    iam.put_role_policy(
        RoleName=denied_name, PolicyName="codebuild-inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17",
                                   "Statement": [logs_stmt, _s3_stmt(bucket)]}))
    repaired_marker = ctx.unique_name("sim2real-repaired-")
    deadline = time.monotonic() + 240
    repaired = _run_build(cb, ctx, denied_project, repaired_marker)
    while repaired["buildStatus"] != "SUCCEEDED" and time.monotonic() < deadline:
        # the grant is eventually consistent; retry the build, never assert off a sleep
        repaired = _run_build(cb, ctx, denied_project, repaired_marker)
    assert repaired["buildStatus"] == "SUCCEEDED", (
        f"after granting s3:PutObject the same project must upload, the build was "
        f"{repaired['buildStatus']!r}; phases={_phases(repaired)!r}"
    )
    repaired_keys = [k for k in _list_keys(s3, bucket)
                     if repaired["id"].split(":")[-1] in k]
    assert len(repaired_keys) == 1, (
        f"the repaired build should land exactly one object, landed {repaired_keys!r}"
    )
    repaired_body = s3.get_object(Bucket=bucket, Key=repaired_keys[0])["Body"].read()
    assert repaired_body == repaired_marker.encode(), (
        f"the repaired build's artifact held {repaired_body[:80]!r}, expected "
        f"{repaired_marker.encode()!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
