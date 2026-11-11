"""list-projects-sort-by-name-and-created-time-sequence."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags



def _delete_role(iam, role_name):
    """Delete an IAM role, removing its inline policies first (cleanup path: best-effort)."""
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


def _create_service_role(ctx):
    """Mint a real CodeBuild-assumable IAM service role so CreateProject validates. Returns its ARN."""
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
    return resp["Role"]["Arn"]


_BUILDSPEC_NOOP = (
    "version: 0.2\n"
    "phases:\n"
    "  build:\n"
    "    commands:\n"
    "      - echo sim2real-noop\n"
)

# NO cache, NO artifacts, both log destinations DISABLED: a project in this shape leaves
# behind no S3 object, no cache bucket and no /aws/codebuild/<project> log group, so the
# only resource to reclaim is the project itself.
_NO_LOGS = {
    "cloudWatchLogs": {"status": "DISABLED"},
    "s3Logs": {"status": "DISABLED"},
}


def _project_args(name, role, **over):
    """Minimal-cost valid CreateProject kwargs: NO_SOURCE + inline buildspec, NO_ARTIFACTS,
    LINUX_CONTAINER / BUILD_GENERAL1_SMALL (never ARM/LARGE/GPU), logs off, no vpcConfig."""
    args = {
        "name": name,
        "source": {"type": "NO_SOURCE", "buildspec": _BUILDSPEC_NOOP},
        "artifacts": {"type": "NO_ARTIFACTS"},
        "cache": {"type": "NO_CACHE"},
        "environment": {
            "type": "LINUX_CONTAINER",
            "image": "aws/codebuild/standard:7.0",
            "computeType": "BUILD_GENERAL1_SMALL",
        },
        "serviceRole": role,
        "logsConfig": dict(_NO_LOGS),
        "tags": [{"key": "sim2real", "value": CHECK}],
    }
    args.update(over)
    return args


def _create_project(cb, ctx, name, role, **over):
    """CreateProject, retrying through IAM trust-policy propagation; registers teardown
    immediately on success. Returns the project dict."""
    deadline = time.monotonic() + 90
    while True:
        try:
            proj = cb.create_project(**_project_args(name, role, **over))["project"]
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            msg = (err.get("Message") or "").lower()
            transient_role = err.get("Code") == "InvalidInputException" and (
                "assume" in msg or "not authorized" in msg
            )
            if transient_role and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: cb.delete_project(name=proj["name"]))
    return proj


def _all_project_names(cb, **kwargs):
    """Every project name, in server order, across pages. Order-preserving: the caller
    asserts a SEQUENCE, so pages are concatenated, never merged into a set."""
    names = []
    token = None
    for _ in range(50):  # bounded: never an unbounded pagination loop
        call = dict(kwargs)
        if token:
            call["nextToken"] = token
        resp = cb.list_projects(**call)
        names.extend(resp.get("projects", []))
        token = resp.get("nextToken")
        if not token:
            break
    return names



CHECK = "list-projects-sort-by-name-and-created-time-sequence"
GROUP = 'project'
SERVICES = ['codebuild']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListProjects honours sortBy/sortOrder exactly: NAME ascending and descending are exact
    reverses, and CREATED_TIME descending is newest-first - asserted as an ordered SEQUENCE, so
    insertion order cannot pass.
    """
    cb = ctx.client("codebuild")
    role = _create_service_role(ctx)  # one role, reused by all three projects
    base = ctx.unique_name("sim2real-behav-proj-")
    a, b, c = f"{base}-a", f"{base}-b", f"{base}-c"

    # Create out of alphabetical order, so name order and creation order disagree.
    for nm in (c, a, b):
        _create_project(cb, ctx, nm, role)
        time.sleep(1.1)  # separate createdTime values, not an assertion wait

    mine = {a, b, c}

    asc = [n for n in _all_project_names(cb, sortBy="NAME", sortOrder="ASCENDING") if n in mine]
    assert asc == [a, b, c], f"NAME/ASCENDING must be a sorted sequence, got {asc}"

    desc = [n for n in _all_project_names(cb, sortBy="NAME", sortOrder="DESCENDING") if n in mine]
    assert desc == [c, b, a], f"NAME/DESCENDING must be a sorted sequence, got {desc}"
    assert desc == list(reversed(asc)), (asc, desc)

    newest = [n for n in _all_project_names(cb, sortBy="CREATED_TIME", sortOrder="DESCENDING")
              if n in mine]
    assert newest == [b, a, c], (
        f"CREATED_TIME/DESCENDING must be newest-first (created c, a, b), got {newest}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
