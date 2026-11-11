"""update-project-absent-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-project-absent-not-found"
GROUP = 'error-semantics'
SERVICES = ['codebuild']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateProject on an absent project name -> ResourceNotFoundException, not a universal
    rejection: the SAME name update_project()s cleanly both before the project is deleted and
    again once it is recreated, so the error is provably about absence and nothing else."""
    cb = ctx.client("codebuild")
    role_arn = _create_service_role(ctx)
    name = ctx.unique_name("sim2real-behav-missing-proj-")

    # --- Positive control: the project exists and UpdateProject on it succeeds.
    _create_project(cb, ctx, name=name, service_role=role_arn)
    resp = cb.update_project(name=name, description="sim2real probe before delete")
    assert resp["project"]["description"] == "sim2real probe before delete", resp

    # --- Break exactly one thing: delete the project. Independent read (BatchGetProjects, a
    # different operation than either Update or Delete) confirms it is gone before we touch it.
    cb.delete_project(name=name)
    _wait_until_absent(cb, name)

    # --- The specific refusal, on the now-absent name.
    code, message = _client_error(
        lambda: cb.update_project(name=name, description="sim2real probe of a missing project")
    )
    assert code == "ResourceNotFoundException", code
    expected = "Project does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # --- Restore: recreate the identifier, then the identical call succeeds again.
    _create_project(cb, ctx, name=name, service_role=role_arn)
    resp = cb.update_project(name=name, description="sim2real probe after recreate")
    assert resp["project"]["description"] == "sim2real probe after recreate", resp


# ===== helpers =====

def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses fails loudly here."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _wait_until_absent(cb, name, *, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = cb.batch_get_projects(names=[name])
        materialized = {p["name"] for p in resp.get("projects", [])}
        last = resp
        if name in resp.get("projectsNotFound", []) and name not in materialized:
            return
        time.sleep(interval_s)
    raise AssertionError(f"{name} still visible {timeout_s}s after DeleteProject: {last!r}")


def _create_service_role(ctx):
    """Mint a real CodeBuild-assumable IAM service role (so CreateProject validates); return its ARN."""
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="codebuild-inline",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                "Resource": "*",
            }],
        }),
    )
    # No fixed sleep for IAM-role propagation: _create_project's own bounded retry on
    # InvalidInputException("...assume...") absorbs the lag with a stated deadline instead.
    return resp["Role"]["Arn"]


def _delete_role(iam, role_name):
    for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    iam.delete_role(RoleName=role_name)


def _create_project(cb, ctx, *, name, service_role):
    """Create a project under an EXACT name (retrying through IAM role-propagation lag)."""
    kwargs = {
        "name": name,
        "source": {
            "type": "NO_SOURCE",
            "buildspec": "version: 0.2\nphases:\n  build:\n    commands:\n      - echo hello\n",
        },
        "artifacts": {"type": "NO_ARTIFACTS"},
        "environment": {
            "type": "LINUX_CONTAINER",
            "image": "aws/codebuild/standard:7.0",
            "computeType": "BUILD_GENERAL1_SMALL",
        },
        "serviceRole": service_role,
        "tags": [{"key": "sim2real", "value": CHECK}],
    }
    deadline = time.monotonic() + 75
    while True:
        try:
            resp = cb.create_project(**kwargs)
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code = err.get("Code")
            msg = (err.get("Message") or "").lower()
            transient_role = code == "InvalidInputException" and (
                "assume" in msg or "not authorized" in msg
            )
            if transient_role and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    proj = resp["project"]
    # DeleteProject on an absent project succeeds, so the second registration is harmless.
    ctx.on_cleanup(lambda: cb.delete_project(name=proj["name"]))
    return proj


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
