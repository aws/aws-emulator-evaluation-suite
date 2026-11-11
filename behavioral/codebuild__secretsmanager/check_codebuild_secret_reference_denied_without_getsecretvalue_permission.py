"""codebuild-secret-reference-denied-without-getsecretvalue-permission."""
from __future__ import annotations

import hashlib
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

_SCENARIO = "codebuild-secret-denied"
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
    # IAM propagation has no condition to poll; _create_project retries through it.
    ctx.client("iam").put_role_policy(
        RoleName=role_name,
        PolicyName="codebuild-inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )


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


def _all_contexts(build):
    return " ".join(
        (c.get("message") or "")
        for p in build.get("phases", []) for c in (p.get("contexts") or []))


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

CHECK = "codebuild-secret-reference-denied-without-getsecretvalue-permission"
GROUP = 'environment'
SERVICES = ['codebuild', 'secretsmanager']


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A build whose role can read only a decoy secret fails before BUILD, naming GetSecretValue and
    exporting nothing; a permitted sibling resolves the secret, and granting access repairs it.
    """
    cb = ctx.client("codebuild")
    sm = ctx.client("secretsmanager")
    iam = ctx.client("iam")

    secret_value = ctx.unique_name("sim2real-secret-value-")
    secret_name, secret_arn = _create_secret(ctx, sm, secret_value)
    _, decoy_arn = _create_secret(ctx, sm, ctx.unique_name("sim2real-decoy-value-"))

    logs_stmt = {"Effect": "Allow",
                 "Action": ["logs:CreateLogGroup", "logs:CreateLogStream",
                            "logs:PutLogEvents"],
                 "Resource": "*"}

    def _secret_stmt(arn):
        return {"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"],
                "Resource": arn}

    # Both roles exist before any build runs, so only the granted secret differs between them.
    ok_role, ok_arn = _create_role(ctx)
    bad_role, bad_arn = _create_role(ctx)
    _put_policy(ctx, ok_role, [logs_stmt, _secret_stmt(secret_arn)])
    _put_policy(ctx, bad_role, [logs_stmt, _secret_stmt(decoy_arn)])

    buildspec = (
        "version: 0.2\n"
        "env:\n"
        "  exported-variables:\n"
        "    - SIM2REAL_DIGEST\n"
        "phases:\n"
        "  build:\n"
        "    commands:\n"
        '      - export SIM2REAL_DIGEST="$(printf \'%s\' "$SIM2REAL_SECRET"'
        " | sha256sum | cut -c1-64)\"\n"
    )
    reference = f"{secret_name}:token"
    expected_digest = hashlib.sha256(secret_value.encode()).hexdigest()

    def _env(role_unused=None):
        return {"type": "LINUX_CONTAINER", "image": _IMAGE,
                "computeType": "BUILD_GENERAL1_SMALL",
                "environmentVariables": [
                    {"name": "SIM2REAL_SECRET", "value": reference,
                     "type": "SECRETS_MANAGER"}]}

    ok_project = ctx.unique_name("sim2real-behav-proj-oksec-")
    bad_project = ctx.unique_name("sim2real-behav-proj-badsec-")
    _create_project(cb, ctx, ok_project, ok_arn, buildspec, environment=_env())
    _create_project(cb, ctx, bad_project, bad_arn, buildspec, environment=_env())

    def _run(project):
        started = _start_build_with_stop_registered(cb, ctx, projectName=project)
        final = _poll_build_terminal(cb, started["id"], timeout_s=240)
        assert final is not None, f"build {started['id']!r} never reported buildComplete"
        return final, dict((v["name"], v["value"])
                           for v in final.get("exportedEnvironmentVariables", []))

    ok_build, ok_exported = _run(ok_project)
    assert ok_build["buildStatus"] == "SUCCEEDED", (
        f"the permitted control build was {ok_build['buildStatus']!r}; phases="
        f"{_phases(ok_build)!r}; contexts={_all_contexts(ok_build)!r}"
    )
    assert ok_exported.get("SIM2REAL_DIGEST") == expected_digest, (
        f"the permitted build computed {ok_exported.get('SIM2REAL_DIGEST')!r}, expected the "
        f"digest of the secret {expected_digest!r}, so the barrier itself did not hold"
    )

    bad_build, bad_exported = _run(bad_project)
    assert bad_build["buildStatus"] == "FAILED", (
        f"a build whose role cannot read its referenced secret must FAIL, got "
        f"{bad_build['buildStatus']!r}; phases={_phases(bad_build)!r}; contexts="
        f"{_all_contexts(bad_build)!r}"
    )
    bad_context = _all_contexts(bad_build)
    assert "secretsmanager:GetSecretValue" in bad_context, (
        f"the failure context did not name the denied secretsmanager action: "
        f"{bad_context!r}"
    )
    assert "SIM2REAL_DIGEST" not in bad_exported, (
        f"the refused build exported a digest, so its buildspec ran despite the unresolved "
        f"secret: {bad_exported!r}"
    )
    assert "BUILD" not in [p.get("phaseType") for p in bad_build.get("phases", [])], (
        f"the container must never reach the BUILD phase when the reference cannot be "
        f"resolved, phases were {_phases(bad_build)!r}"
    )
    assert secret_value not in json.dumps(bad_build, default=str), (
        "the secret plaintext appeared in the response for a build that was denied it"
    )

    iam.put_role_policy(
        RoleName=bad_role, PolicyName="codebuild-inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17",
                                   "Statement": [logs_stmt, _secret_stmt(secret_arn)]}))
    deadline = time.monotonic() + 240
    repaired, repaired_exported = _run(bad_project)
    while repaired["buildStatus"] != "SUCCEEDED" and time.monotonic() < deadline:
        # The grant is eventually consistent; retry the build until the deadline.
        repaired, repaired_exported = _run(bad_project)
    assert repaired["buildStatus"] == "SUCCEEDED", (
        f"after granting secretsmanager:GetSecretValue on the referenced secret the same "
        f"project must build, got {repaired['buildStatus']!r}; phases={_phases(repaired)!r}"
    )
    assert repaired_exported.get("SIM2REAL_DIGEST") == expected_digest, (
        f"the repaired build computed {repaired_exported.get('SIM2REAL_DIGEST')!r}, expected "
        f"{expected_digest!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
