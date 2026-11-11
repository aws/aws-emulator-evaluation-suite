"""codebuild-missing-declared-artifact-rejects-upload-and-no-object-lands."""
from __future__ import annotations

import json
import time


from botocore.exceptions import ClientError

from behavioral_harness import tags

# ===== helpers =====

_SCENARIO = "codebuild-missing-artifact"
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
    # IAM propagation exposes no condition to poll here; the bounded retry inside
    # _create_project (deadline, not a sleep) is what makes this correct.
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

# ===== check =====

CHECK = "codebuild-missing-declared-artifact-rejects-upload-and-no-object-lands"
GROUP = 'artifacts'
SERVICES = ['codebuild', 's3']


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A build whose commands succeed but never create the file named in artifacts.files ends
    FAILED in UPLOAD_ARTIFACTS with an empty S3 namespace, while the identical project that creates
    the file lands an object holding the exact bytes the container wrote."""
    cb = ctx.client("codebuild")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-cb-noart-").lower().replace("_", "-")
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

    def _spec(create_it):
        make = ('      - printf \'%s\' "$SIM2REAL_MARKER" > never-written.txt\n'
                if create_it else "")
        return (
            "version: 0.2\n"
            "phases:\n"
            "  build:\n"
            "    commands:\n"
            "      - echo sim2real-build-phase-ran\n"
            + make +
            "  post_build:\n"
            "    commands:\n"
            "      - echo sim2real-post-build-phase-ran\n"
            "artifacts:\n"
            "  files:\n"
            "    - never-written.txt\n"
        )

    name = ctx.unique_name("sim2real-behav-proj-noart-")
    _create_project(
        cb, ctx, name, role, _spec(False),
        artifacts={"type": "S3", "location": bucket, "path": "out", "name": "build",
                   "namespaceType": "BUILD_ID", "packaging": "NONE",
                   "encryptionDisabled": True},
    )

    # --- break exactly one thing: the declared artifact is never created ---------
    started = _start_build_with_stop_registered(cb, ctx, projectName=name)
    bad = _poll_build_terminal(cb, started["id"], timeout_s=240)
    assert bad is not None, f"build {started['id']!r} never reported buildComplete"

    assert bad["buildStatus"] == "FAILED", (
        f"expected FAILED for a missing declared artifact, got {bad['buildStatus']!r}; "
        f"phases={_phases(bad)!r}"
    )
    by_type = {p.get("phaseType"): p for p in bad.get("phases", [])}
    upload = by_type.get("UPLOAD_ARTIFACTS")
    assert upload is not None and upload.get("phaseStatus") == "FAILED", (
        f"the failure must land in UPLOAD_ARTIFACTS, phases were {_phases(bad)!r}"
    )
    for earlier in ("BUILD", "POST_BUILD"):
        assert by_type.get(earlier, {}).get("phaseStatus") == "SUCCEEDED", (
            f"{earlier} also failed, so this is a command failure rather than an upload "
            f"failure: {_phases(bad)!r}"
        )
    upload_context = " ".join(
        (c.get("message") or "") for c in (upload.get("contexts") or []))
    assert "no matching artifact paths found" in upload_context.lower(), (
        f"UPLOAD_ARTIFACTS context did not report the missing artifact path: "
        f"{upload_context!r}"
    )

    bad_uuid = bad["id"].split(":")[-1]
    all_keys = _list_keys(s3, bucket)
    bad_keys = [k for k in all_keys if bad_uuid in k]
    assert bad_keys == [], (
        f"objects appeared under the namespace of a build whose artifact upload FAILED: "
        f"{bad_keys!r} (every key in the bucket: {all_keys!r})"
    )

    # --- positive control: the same project, the file created --------------------
    marker = ctx.unique_name("sim2real-marker-")
    started2 = _start_build_with_stop_registered(
        cb, ctx, projectName=name, buildspecOverride=_spec(True),
        environmentVariablesOverride=[
            {"name": "SIM2REAL_MARKER", "value": marker, "type": "PLAINTEXT"}],
    )
    good = _poll_build_terminal(cb, started2["id"], timeout_s=240)
    assert good is not None, f"control build {started2['id']!r} never reported buildComplete"
    assert good["buildStatus"] == "SUCCEEDED", (
        f"the control build must SUCCEED on the same project, got "
        f"{good['buildStatus']!r}; phases={_phases(good)!r}"
    )

    good_uuid = good["id"].split(":")[-1]
    good_keys = [k for k in _list_keys(s3, bucket) if good_uuid in k]
    assert len(good_keys) == 1, (
        f"the control build should land exactly one object, landed {good_keys!r}"
    )
    body = s3.get_object(Bucket=bucket, Key=good_keys[0])["Body"].read()
    assert body == marker.encode(), (
        f"control artifact at {good_keys[0]!r} contained {body[:80]!r}, expected "
        f"{marker.encode()!r}"
    )
    assert _list_keys(s3, bucket) == good_keys, (
        f"only the control build should have left an object, bucket holds "
        f"{_list_keys(s3, bucket)!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
