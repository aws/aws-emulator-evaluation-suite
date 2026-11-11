"""cfn-codebuild-project-in-place-update-builds-retained-replacement-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-codebuild-project-in-place-update-builds-retained-replacement-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "codebuild"]

#: A stack operation takes seconds to a few minutes; the bound only stops a hung poll.
_STACK_S = 600.0
#: A build provisions and finishes in a few minutes; the bound only stops a hung poll.
_BUILD_S = 600.0
#: A role reaches CodeBuild within seconds; the bound only stops a retry loop.
_TRUST_S = 120.0
#: A change or delete reaches every read within seconds; the bound only stops a hung poll.
_PROPAGATE_S = 60.0
_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_IAM = ["CAPABILITY_IAM"]
_REPLACING = (
    "Requested update requires the creation of a new physical resource; hence creating one."
)
#: CreateProject's refusal of a role CodeBuild cannot assume yet; CreateStack is retried on it only.
_NOT_ASSUMABLE = "is not authorized to perform: sts:AssumeRole"
_IMAGE = "aws/codebuild/amazonlinux2-x86_64-standard:5.0"
#: The build exports GREETING after appending to the value the project's environment sets.
_BUILDSPEC = (
    "version: 0.2\n"
    "env:\n"
    "  exported-variables:\n"
    "    - GREETING\n"
    "phases:\n"
    "  build:\n"
    "    commands:\n"
    '      - export GREETING="${GREETING}-built"\n'
)


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:deploy",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """An AWS::CodeBuild::Project survives create, in-place update, retained replacement and delete.

    BatchGetProjects reads back each template, a build of the updated project exports the new
    environment value, and a Name change under UpdateReplacePolicy Retain keeps the old project.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-codebuild-project.html
    """
    cfn = ctx.client("cloudformation")
    codebuild = ctx.client("codebuild")

    stack_name = ctx.unique_name("sim2real-cfnreal-cb-")
    project_v1 = ctx.unique_name("sim2real-cfnreal-cb-a-")
    project_v2 = ctx.unique_name("sim2real-cfnreal-cb-b-")

    # The replaced project outlives the stack, so the check deletes it itself; DeleteProject of
    # a name that does not exist succeeds.
    ctx.on_cleanup(lambda: codebuild.delete_project(name=project_v1))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))

    # ---- 1. create: CloudFormation view, CodeBuild view ---------------------------------------
    stack_id = _create_retrying_role(
        ctx, cfn, stack_name, _template(project_v1, "reality check project", 8, "one")
    )
    _assert_tracks(cfn, stack_id, "Project", project_v1)
    partition = stack_id.split(":")[1]
    outputs = _outputs(cfn, stack_id)
    want_arn = f"arn:{partition}:codebuild:{ctx.region}:{ctx.account}:project/{project_v1}"
    assert outputs["ProjectArn"] == want_arn, (
        f"GetAtt Project.Arn must be {want_arn!r}, got {outputs['ProjectArn']!r}"
    )
    role_arn = outputs["RoleArn"]
    project = _project(codebuild, project_v1)
    assert project["arn"] == want_arn, f"BatchGetProjects arn {project['arn']!r}"
    _assert_project(project, role_arn, "reality check project", 8, "one")

    # ---- 2. in place: Description, TimeoutInMinutes and the environment variable --------------
    body = _template(project_v1, "reality check project, updated", 9, "two")
    _assert_updated_in_place(
        _update(ctx, cfn, stack_id, "Project", body, Capabilities=_IAM), project_v1
    )
    _assert_tracks(cfn, stack_id, "Project", project_v1)
    project = _poll(
        ctx,
        lambda: _project(codebuild, project_v1),
        lambda p: p.get("timeoutInMinutes") == 9,
        cap_s=_PROPAGATE_S,
        what=f"BatchGetProjects on {project_v1} to read the updated timeout",
    )
    assert project["arn"] == want_arn, f"an in-place update keeps the project ARN, got {project!r}"
    _assert_project(project, role_arn, "reality check project, updated", 9, "two")

    # Behaviour: a build of the updated project runs the buildspec with the new value.
    build_id = codebuild.start_build(projectName=project_v1)["build"]["id"]
    ctx.on_cleanup(lambda: _stop_build(codebuild, build_id))
    build = _poll(
        ctx,
        lambda: codebuild.batch_get_builds(ids=[build_id])["builds"][0],
        lambda b: b.get("buildComplete") is True,
        cap_s=_BUILD_S,
        interval_s=5.0,
        what=f"build {build_id} to complete",
    )
    assert (build["projectName"], build["buildStatus"]) == (project_v1, "SUCCEEDED"), (
        f"the build of {project_v1!r} must succeed: {build.get('buildStatus')!r}, "
        f"phases {[(p.get('phaseType'), p.get('phaseStatus')) for p in build.get('phases', [])]!r}"
    )
    assert build.get("exportedEnvironmentVariables") == [
        {"name": "GREETING", "value": "two-built"}
    ], (
        f"the build must export the updated value with the buildspec's suffix, got "
        f"{build.get('exportedEnvironmentVariables')!r}"
    )

    # ---- 3. Name forces replacement; UpdateReplacePolicy Retain keeps the old project ---------
    body = _template(project_v2, "reality check project, updated", 9, "two")
    rows = _update(ctx, cfn, stack_id, "Project", body, Capabilities=_IAM)
    _assert_replaced_and_retained(rows, project_v1, project_v2)
    _assert_tracks(cfn, stack_id, "Project", project_v2)
    new = _project(codebuild, project_v2)
    assert new["arn"] == want_arn.replace(project_v1, project_v2), f"replacement arn {new['arn']!r}"
    _assert_project(new, role_arn, "reality check project, updated", 9, "two")
    old = _project(codebuild, project_v1)
    assert old["arn"] == want_arn, f"the retained project {project_v1!r} must remain, got {old!r}"
    _assert_project(old, role_arn, "reality check project, updated", 9, "two")

    # ---- 4. DeleteStack: the project it owns is gone, the retained one stays -----------------
    _delete_and_confirm(ctx, cfn, stack_id)
    gone = _poll(
        ctx,
        lambda: codebuild.batch_get_projects(names=[project_v2]),
        lambda r: r["projects"] == [],
        cap_s=_PROPAGATE_S,
        what=f"BatchGetProjects to stop describing {project_v2}",
    )
    assert gone["projectsNotFound"] == [project_v2], (
        f"BatchGetProjects must list {project_v2!r} as not found, got {gone['projectsNotFound']!r}"
    )
    assert _project(codebuild, project_v1)["arn"] == want_arn, "the retained project survives"


def _template(name: str, description: str, timeout_min: int, greeting: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                # No policy: the build reads no source, writes no artifact and sends no logs.
                "BuildRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "codebuild.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                    },
                },
                "Project": {
                    "Type": "AWS::CodeBuild::Project",
                    # Name is create-only, so a new name replaces the project.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "Name": name,
                        "Description": description,
                        "ServiceRole": {"Fn::GetAtt": ["BuildRole", "Arn"]},
                        "Source": {"Type": "NO_SOURCE", "BuildSpec": _BUILDSPEC},
                        "Artifacts": {"Type": "NO_ARTIFACTS"},
                        "Environment": {
                            "Type": "LINUX_CONTAINER",
                            "ComputeType": "BUILD_GENERAL1_SMALL",
                            "Image": _IMAGE,
                            "EnvironmentVariables": [
                                {"Name": "GREETING", "Type": "PLAINTEXT", "Value": greeting}
                            ],
                        },
                        "TimeoutInMinutes": timeout_min,
                        "QueuedTimeoutInMinutes": 5,
                        "LogsConfig": {"CloudWatchLogs": {"Status": "DISABLED"}},
                    },
                },
            },
            "Outputs": {
                "ProjectArn": {"Value": {"Fn::GetAtt": ["Project", "Arn"]}},
                "RoleArn": {"Value": {"Fn::GetAtt": ["BuildRole", "Arn"]}},
            },
        }
    )


def _project(codebuild, name: str) -> dict:
    got = codebuild.batch_get_projects(names=[name])
    assert got["projectsNotFound"] == [] and len(got["projects"]) == 1, (
        f"BatchGetProjects must describe exactly {name!r}, got {got!r}"
    )
    return got["projects"][0]


def _assert_project(
    project: dict, role_arn: str, description: str, timeout_min: int, greeting: str
) -> None:
    """CodeBuild's view: the project carries exactly the template's settings."""
    env = project["environment"]
    got = {
        "description": project.get("description"),
        "serviceRole": project.get("serviceRole"),
        "source": (project["source"].get("type"), project["source"].get("buildspec")),
        "artifacts": project["artifacts"].get("type"),
        "environment": (env.get("type"), env.get("computeType"), env.get("image")),
        "environmentVariables": env.get("environmentVariables"),
        "timeoutInMinutes": project.get("timeoutInMinutes"),
        "queuedTimeoutInMinutes": project.get("queuedTimeoutInMinutes"),
        "logs": project.get("logsConfig", {}).get("cloudWatchLogs", {}).get("status"),
    }
    want = {
        "description": description,
        "serviceRole": role_arn,
        "source": ("NO_SOURCE", _BUILDSPEC),
        "artifacts": "NO_ARTIFACTS",
        "environment": ("LINUX_CONTAINER", "BUILD_GENERAL1_SMALL", _IMAGE),
        "environmentVariables": [{"name": "GREETING", "value": greeting, "type": "PLAINTEXT"}],
        "timeoutInMinutes": timeout_min,
        "queuedTimeoutInMinutes": 5,
        "logs": "DISABLED",
    }
    assert got == want, f"BatchGetProjects must read back the template: {got!r}, want {want!r}"


def _outputs(cfn, stack_id: str) -> dict:
    return {o["OutputKey"]: o.get("OutputValue") for o in _stack(cfn, stack_id).get("Outputs", [])}


def _stop_build(codebuild, build_id: str) -> None:
    """Teardown: stop the build unless it already finished."""
    build = codebuild.batch_get_builds(ids=[build_id])["builds"]
    if build and not build[0].get("buildComplete"):
        codebuild.stop_build(id=build_id)


def _create_retrying_role(ctx, cfn, stack_name: str, body: str) -> str:
    """CreateStack until CREATE_COMPLETE and return the StackId.

    A fresh role can reach CodeBuild only seconds after IAM returns it, and no read shows when;
    a rollback for exactly that reason is deleted and created again, within _TRUST_S.
    """
    deadline = time.monotonic() + _budget_s(ctx, _TRUST_S)
    while True:
        stack_id = cfn.create_stack(
            StackName=stack_name, Capabilities=_IAM, Tags=_TAGS, TemplateBody=body
        )["StackId"]
        created = _settle(ctx, cfn, stack_id)
        if created["StackStatus"] == "CREATE_COMPLETE":
            return stack_id
        reasons = [
            e.get("ResourceStatusReason") or ""
            for e in _events(cfn, stack_id)
            if e["LogicalResourceId"] == "Project" and e["ResourceStatus"] == "CREATE_FAILED"
        ]
        retry = (
            created["StackStatus"] == "ROLLBACK_COMPLETE"
            and len(reasons) == 1
            and _NOT_ASSUMABLE in reasons[0]
            and time.monotonic() < deadline
        )
        assert retry, (
            f"create ended {created['StackStatus']!r}: {created.get('StackStatusReason')!r}; "
            f"Project failures {reasons!r}"
        )
        _delete_and_confirm(ctx, cfn, stack_id)
        time.sleep(5.0)


# ===== stack helpers =====


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    Teardown passes ctx=None and keeps the fixed cap: the runner's deadline does not cover it.
    """
    left = None if ctx is None else ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx) -> bool:
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = None if ctx is None else ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, probe, done, *, cap_s: float, what: str, interval_s: float = 2.0):
    """Call probe() until done(result) holds and return it; ctx=None (teardown) is not budgeted."""
    timeout_s = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"the run budget ended while waiting for {what}; not graded")
            raise AssertionError(f"{what} not reached within {timeout_s:.0f}s; last {last!r}")
        time.sleep(interval_s)


def _stack(cfn, stack_id: str) -> dict:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _settle(ctx, cfn, stack_id: str) -> dict:
    """The stack once no operation (cleanup phase included) is in progress on it."""
    return _poll(
        ctx,
        lambda: _stack(cfn, stack_id),
        lambda s: not s["StackStatus"].endswith("_IN_PROGRESS"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} settled",
    )


def _physical(cfn, stack_id: str, logical_id: str) -> str:
    return cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId=logical_id)[
        "StackResourceDetail"
    ]["PhysicalResourceId"]


def _assert_tracks(cfn, stack_id: str, logical_id: str, expected: str) -> None:
    """CloudFormation's view: the stack resource carries the expected PhysicalResourceId."""
    got = _physical(cfn, stack_id, logical_id)
    assert got == expected, f"the stack must track {logical_id} as {expected!r}, got {got!r}"


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first (the API pages newest first)."""
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out[::-1]


def _update(ctx, cfn, stack_id: str, logical_id: str, body: str, **kw) -> list[tuple]:
    """UpdateStack to body, assert UPDATE_COMPLETE and return the update's rows for logical_id.

    A row is (ResourceStatus, ResourceStatusReason, PhysicalResourceId), oldest first.
    """
    before = len(_events(cfn, stack_id))
    cfn.update_stack(StackName=stack_id, TemplateBody=body, **kw)
    stack = _settle(ctx, cfn, stack_id)
    events = _events(cfn, stack_id)[before:]
    failed = [
        (e["LogicalResourceId"], e.get("ResourceStatusReason"))
        for e in events
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    assert stack["StackStatus"] == "UPDATE_COMPLETE", (
        f"update ended {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}; {failed!r}"
    )
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["LogicalResourceId"] == logical_id
    ]


def _in_order(rows: list[tuple], wanted: list[tuple]) -> bool:
    """Whether every wanted row occurs in rows in that order; a None field matches any value."""
    remaining = iter(rows)
    return all(
        any(all(w is None or w == v for w, v in zip(want, row, strict=True)) for row in remaining)
        for want in wanted
    )


def _assert_updated_in_place(rows: list[tuple], physical: str) -> None:
    """The update completed on the same physical id and reported no replacement or delete."""
    assert _in_order(
        rows, [("UPDATE_IN_PROGRESS", None, None), ("UPDATE_COMPLETE", None, physical)]
    ), f"an in-place update must progress and complete on {physical!r}: {rows!r}"
    replacing = [r for r in rows if r[1] == _REPLACING or r[0].startswith("DELETE_")]
    assert replacing == [], f"an in-place update must not replace anything: {replacing!r}"


def _assert_replaced_and_retained(rows: list[tuple], old: str, new: str) -> None:
    """The update reported a replacement, completed on the new id and skipped deleting the old."""
    assert _in_order(
        rows,
        [
            ("UPDATE_IN_PROGRESS", _REPLACING, None),
            ("UPDATE_COMPLETE", None, new),
            ("DELETE_SKIPPED", None, old),
        ],
    ), (
        f"the replacement must report creating a new resource, complete as {new!r} and skip "
        f"deleting {old!r} (UpdateReplacePolicy Retain), in that order: {rows!r}"
    )
    deleted = [r for r in rows if r[0] in ("DELETE_IN_PROGRESS", "DELETE_COMPLETE")]
    assert deleted == [], f"UpdateReplacePolicy Retain must delete nothing: {deleted!r}"


def _delete_and_confirm(ctx, cfn, stack_id: str) -> None:
    """DeleteStack by StackId and assert it reaches DELETE_COMPLETE."""
    cfn.delete_stack(StackName=stack_id)
    final = _poll(
        ctx,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: not s.endswith("_IN_PROGRESS"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} deleted",
    )
    assert final == "DELETE_COMPLETE", (
        f"DeleteStack ended {final!r}: {_stack(cfn, stack_id).get('StackStatusReason')!r}"
    )


def _delete_stack(cfn, stack_name: str) -> None:
    """Teardown: delete the stack by its StackId and wait; DELETE_FAILED or a timeout raises."""
    try:
        stack_id = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {stack_name} does not exist":
            return
        raise
    status = _poll(
        None,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: not s.endswith("_IN_PROGRESS"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} settled before teardown",
    )
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(
        None,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} deleted",
    )
    if final != "DELETE_COMPLETE":
        raise AssertionError(
            f"stack {stack_id} ended {final}: {_stack(cfn, stack_id).get('StackStatusReason')!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
