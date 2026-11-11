"""codebuild-secondary-artifacts-land-at-their-own-declared-locations."""
from __future__ import annotations

import hashlib
import io
import json
import random
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

# ===== helpers =====
# _poll_build_terminal raises on timeout, and _poll_keys polls the object listing until it settles.

_SCENARIO = "codebuild-secondary-artifacts"
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
    """Every key under `prefix`, paginated: page one is not a bound."""
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return sorted(keys)


def _poll_keys(s3, bucket, expected_count, *, timeout_s, interval_s=3.0):
    """Bounded wait for the bucket listing to show `expected_count` keys. Returns the last
    listing so the caller's assertion can quote what really landed; the caller's exact-equality
    assertion is what fails, which reads far better than a timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        keys = _list_keys(s3, bucket)
        if len(keys) >= expected_count or time.monotonic() >= deadline:
            return keys
        time.sleep(interval_s)


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
    # Trust propagation exposes no condition to poll, so this bounded retry IS the wait.
    deadline = time.monotonic() + 180
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


def _poll_build_terminal(cb, build_id, *, timeout_s, interval_s=5.0):
    """Poll BatchGetBuilds until buildComplete, bounded by a deadline. RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        got = cb.batch_get_builds(ids=[build_id])
        builds = got.get("builds", [])
        assert builds, (
            f"BatchGetBuilds lost build {build_id!r}: buildsNotFound="
            f"{got.get('buildsNotFound')!r}"
        )
        last = builds[0]
        if last.get("buildComplete") is True:
            return last
        assert time.monotonic() < deadline, (
            f"build {build_id!r} never reported buildComplete within {timeout_s}s; last "
            f"buildStatus={last.get('buildStatus')!r} currentPhase="
            f"{last.get('currentPhase')!r}"
        )
        time.sleep(interval_s)


def _phases(build):
    return [(p.get("phaseType"), p.get("phaseStatus")) for p in build.get("phases", [])]


def _sole_zip_member(body, expected_name):
    """The bytes of the single member of a ZIP, asserting the member list exactly."""
    with zipfile.ZipFile(io.BytesIO(body)) as zf:
        names = zf.namelist()
        assert names == [expected_name], (
            f"the packaged artifact must hold exactly its own declared file "
            f"[{expected_name!r}], it holds {names!r} - a build that packages every file into "
            f"every artifact looks exactly like this"
        )
        return zf.read(expected_name)


# ===== check =====

CHECK = "codebuild-secondary-artifacts-land-at-their-own-declared-locations"
GROUP = 'artifacts'
SERVICES = ['codebuild', 's3']


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A build declaring one primary and two secondary artifacts leaves exactly three S3 objects,
    each ZIP holding only its own declared file, and BatchGetBuilds reports each secondary artifact
    under its artifactIdentifier with a location and md5sum matching the bytes in the bucket."""
    cb = ctx.client("codebuild")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-cb-secart-").lower().replace("_", "-")
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

    # One seed, three DIFFERENT derivations, so no artifact's payload can stand in for another's.
    seed = random.SystemRandom().randrange(1000, 10000)
    expected = {
        "primary": str(seed * 3 + 1).encode(),
        "alpha": str(seed * 5 + 2).encode(),
        "beta": str(seed * 7 + 3).encode(),
    }
    assert len(set(expected.values())) == 3, (
        f"the three derivations must be distinct for seed={seed}: {expected!r}"
    )

    buildspec = (
        "version: 0.2\n"
        "phases:\n"
        "  build:\n"
        "    commands:\n"
        '      - printf \'%s\' "$(( SIM2REAL_SEED * 3 + 1 ))" > primary.txt\n'
        '      - printf \'%s\' "$(( SIM2REAL_SEED * 5 + 2 ))" > alpha.txt\n'
        '      - printf \'%s\' "$(( SIM2REAL_SEED * 7 + 3 ))" > beta.txt\n'
        "artifacts:\n"
        "  files:\n"
        "    - primary.txt\n"
        "  secondary-artifacts:\n"
        "    alpha:\n"
        "      files:\n"
        "        - alpha.txt\n"
        "    beta:\n"
        "      files:\n"
        "        - beta.txt\n"
    )

    def _s3_block(path, name, identifier=None):
        block = {"type": "S3", "location": bucket, "path": path, "name": name,
                 "namespaceType": "NONE", "packaging": "ZIP", "encryptionDisabled": True}
        if identifier is not None:
            block["artifactIdentifier"] = identifier
        return block

    name = ctx.unique_name("sim2real-behav-proj-secart-")
    _create_project(
        cb, ctx, name, role, buildspec,
        artifacts=_s3_block("primary", "primary.zip"),
        secondaryArtifacts=[_s3_block("alpha", "alpha.zip", "alpha"),
                            _s3_block("beta", "beta.zip", "beta")],
    )

    started = _start_build_with_stop_registered(
        cb, ctx, projectName=name,
        environmentVariablesOverride=[
            {"name": "SIM2REAL_SEED", "value": str(seed), "type": "PLAINTEXT"}])
    build = _poll_build_terminal(cb, started["id"], timeout_s=300)

    assert build["buildStatus"] == "SUCCEEDED", (
        f"the build must succeed for its artifacts to be evidence; got "
        f"{build['buildStatus']!r}; phases={_phases(build)!r}; "
        f"contexts={[p.get('contexts') for p in build.get('phases', [])]!r}"
    )
    upload = next((p for p in build.get("phases", [])
                   if p.get("phaseType") == "UPLOAD_ARTIFACTS"), None)
    assert upload is not None and upload.get("phaseStatus") == "SUCCEEDED", (
        f"UPLOAD_ARTIFACTS must be SUCCEEDED for three declared artifacts; got {upload!r}; "
        f"phases={_phases(build)!r}"
    )

    # --- exactly three objects, at exactly the three declared keys ------------------
    keys = {"primary": "primary/primary.zip",
            "alpha": "alpha/alpha.zip",
            "beta": "beta/beta.zip"}
    listed = _poll_keys(s3, bucket, len(keys), timeout_s=120)
    assert listed == sorted(keys.values()), (
        f"the build must leave exactly one object per declared artifact location "
        f"{sorted(keys.values())!r}; the bucket holds {listed!r}"
    )

    # --- each ZIP holds exactly its own file, with its own derived payload -----------
    bodies = {}
    for label, key in keys.items():
        bodies[label] = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        member = f"{label}.txt"
        payload = _sole_zip_member(bodies[label], member)
        assert payload == expected[label], (
            f"the {label!r} artifact at {key!r} must contain {expected[label]!r} (derived from "
            f"seed={seed}), it contains {payload[:80]!r}"
        )

    # --- CodeBuild's own report must match, per artifactIdentifier -------------------
    primary = build.get("artifacts") or {}
    assert (primary.get("location") or "").endswith(f"{bucket}/{keys['primary']}"), (
        f"the primary artifact's reported location must end with "
        f"{bucket}/{keys['primary']!r}; it reports {primary.get('location')!r}"
    )
    assert primary.get("md5sum") == hashlib.md5(bodies["primary"]).hexdigest(), (
        f"CodeBuild reported md5sum {primary.get('md5sum')!r} for the primary artifact whose "
        f"bytes in S3 hash to {hashlib.md5(bodies['primary']).hexdigest()!r}; "
        f"artifacts={primary!r}"
    )

    secondary = build.get("secondaryArtifacts") or []
    by_id = {a.get("artifactIdentifier"): a for a in secondary}
    assert sorted(by_id) == ["alpha", "beta"], (
        f"BatchGetBuilds must report exactly the two declared secondary artifacts keyed by "
        f"their artifactIdentifiers ['alpha', 'beta']; it reports {sorted(by_id)!r} "
        f"(raw: {secondary!r})"
    )
    for label in ("alpha", "beta"):
        entry = by_id[label]
        assert (entry.get("location") or "").endswith(f"{bucket}/{keys[label]}"), (
            f"secondary artifact {label!r} must report its OWN location ending "
            f"{bucket}/{keys[label]!r}; it reports {entry.get('location')!r}. A target that "
            f"routes every artifact to one location looks exactly like this."
        )
        assert entry.get("md5sum") == hashlib.md5(bodies[label]).hexdigest(), (
            f"CodeBuild reported md5sum {entry.get('md5sum')!r} for secondary artifact "
            f"{label!r}, whose bytes in S3 hash to "
            f"{hashlib.md5(bodies[label]).hexdigest()!r}; entry={entry!r}"
        )
    assert by_id["alpha"]["location"] != by_id["beta"]["location"], (
        f"the two secondary artifacts must report DISTINCT locations; both report "
        f"{by_id['alpha']['location']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
