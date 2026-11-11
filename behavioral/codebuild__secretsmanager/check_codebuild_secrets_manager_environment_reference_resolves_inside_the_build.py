"""codebuild-secrets-manager-environment-reference-resolves-inside-the-build."""
from __future__ import annotations

import hashlib
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

_SCENARIO = "codebuild-secret-resolves"
_IMAGE = "aws/codebuild/standard:7.0"


def _delete_role(iam, role_name):
    """Delete an IAM role after its inline policies, tolerating NoSuchEntity."""
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


def _create_role(ctx):
    """Mint a CodeBuild-assumable role with no permissions yet. Returns (name, arn)."""
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
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    return role_name, arn


def _put_policy(ctx, role_name, statements):
    ctx.client("iam").put_role_policy(
        RoleName=role_name,
        PolicyName="codebuild-inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    # IAM propagation has no condition to poll; _create_project retries through it.


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
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
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


def _create_secret(ctx, sm, value):
    """Create a secret holding {"token": value}; register the forced delete immediately."""
    name = ctx.unique_name("sim2real-behav-cb-sec-")
    arn = sm.create_secret(
        Name=name,
        SecretString=json.dumps({"token": value}),
        Description="sim2real behavioral codebuild secret reference",
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
    )["ARN"]
    ctx.on_cleanup(
        lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True))
    return name, arn


# ===== check =====

CHECK = "codebuild-secrets-manager-environment-reference-resolves-inside-the-build"
GROUP = 'environment'
SERVICES = ['codebuild', 'secretsmanager']


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A SECRETS_MANAGER environment variable resolves to the secret's plaintext inside the build
    (matching SHA-256 and length), while the project stores only the reference and no CodeBuild
    response contains the plaintext.
    """
    cb = ctx.client("codebuild")
    sm = ctx.client("secretsmanager")

    secret_value = ctx.unique_name("sim2real-secret-value-")
    secret_name, secret_arn = _create_secret(ctx, sm, secret_value)
    json_key = "token"

    role_name, role_arn = _create_role(ctx)
    _put_policy(ctx, role_name, [
        {"Effect": "Allow",
         "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
         "Resource": "*"},
        {"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"],
         "Resource": secret_arn},
    ])

    buildspec = (
        "version: 0.2\n"
        "env:\n"
        "  exported-variables:\n"
        "    - SIM2REAL_DIGEST\n"
        "    - SIM2REAL_LEN\n"
        "phases:\n"
        "  build:\n"
        "    commands:\n"
        '      - export SIM2REAL_DIGEST="$(printf \'%s\' "$SIM2REAL_SECRET"'
        " | sha256sum | cut -c1-64)\"\n"
        '      - export SIM2REAL_LEN="$(printf \'%s\' "$SIM2REAL_SECRET" | wc -c)"\n'
    )

    reference = f"{secret_name}:{json_key}"
    name = ctx.unique_name("sim2real-behav-proj-sec-")
    _create_project(
        cb, ctx, name, role_arn, buildspec,
        environment={"type": "LINUX_CONTAINER", "image": _IMAGE,
                     "computeType": "BUILD_GENERAL1_SMALL",
                     "environmentVariables": [
                         {"name": "SIM2REAL_SECRET", "value": reference,
                          "type": "SECRETS_MANAGER"}]},
    )

    started = _start_build_with_stop_registered(cb, ctx, projectName=name)
    build = _poll_build_terminal(cb, started["id"], timeout_s=240)
    assert build is not None, f"build {started['id']!r} never reported buildComplete"
    assert build["buildStatus"] == "SUCCEEDED", (
        f"build was {build['buildStatus']!r}; phases={_phases(build)!r}; contexts="
        f"{[p.get('contexts') for p in build.get('phases', [])]!r}"
    )

    exported = dict((v["name"], v["value"])
                    for v in build.get("exportedEnvironmentVariables", []))
    assert exported.get("SIM2REAL_DIGEST") == hashlib.sha256(
            secret_value.encode()).hexdigest(), (
        f"the build computed {exported.get('SIM2REAL_DIGEST')!r} over what the shell saw, "
        f"expected the digest of the secret's plaintext, "
        f"{hashlib.sha256(secret_value.encode()).hexdigest()!r}; exported={exported!r}"
    )
    assert exported.get("SIM2REAL_LEN") == str(len(secret_value)), (
        f"the shell saw a value {exported.get('SIM2REAL_LEN')!r} bytes long, expected "
        f"{len(secret_value)!r} - the reference string is "
        f"{len(reference)!r} bytes, so this rules out the reference being passed through"
    )

    stored = cb.batch_get_projects(names=[name])["projects"][0]
    stored_vars = stored["environment"].get("environmentVariables", [])
    assert [(v["name"], v["value"], v["type"]) for v in stored_vars] == [
            ("SIM2REAL_SECRET", reference, "SECRETS_MANAGER")], (
        f"the project must store the reference typed as SECRETS_MANAGER, it stores "
        f"{stored_vars!r}"
    )
    assert secret_value not in json.dumps(build, default=str), (
        "the resolved secret plaintext appeared in the BatchGetBuilds response"
    )
    assert secret_value not in json.dumps(stored, default=str), (
        "the resolved secret plaintext appeared in the BatchGetProjects response"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
