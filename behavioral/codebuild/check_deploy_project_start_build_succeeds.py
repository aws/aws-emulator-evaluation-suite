"""deploy-project-start-build-succeeds."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "deploy-project-start-build-succeeds"
GROUP = "deploy"
SERVICES = ["codebuild"]

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  ProjectName:
    Type: String
Resources:
  BuildRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: codebuild.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: logs
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                Resource: "*"
  Project:
    Type: AWS::CodeBuild::Project
    Properties:
      Name: !Ref ProjectName
      ServiceRole: !GetAtt BuildRole.Arn
      Artifacts:
        Type: NO_ARTIFACTS
      Environment:
        Type: LINUX_CONTAINER
        ComputeType: BUILD_GENERAL1_SMALL
        Image: aws/codebuild/amazonlinux2-x86_64-standard:5.0
      Source:
        Type: NO_SOURCE
        BuildSpec: |
          version: 0.2
          phases:
            build:
              commands:
                - echo starting
                - sleep 120
Outputs:
  ProjectName:
    Value: !Ref Project
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CodeBuild project deployed via CloudFormation can immediately StartBuild, the
    build progresses past SUBMITTED (a real state-machine transition, not a stub), and
    StopBuild drives it to a terminal STOPPED state observable via BatchGetBuilds."""
    project_name = ctx.unique_name("sim2real-behav-cfnproj-")
    outputs = _deploy_cfn(ctx, _TEMPLATE, {"ProjectName": project_name})
    assert outputs["ProjectName"] == project_name, (
        f"expected stack output ProjectName {project_name!r}, got {outputs.get('ProjectName')!r}"
    )

    codebuild = ctx.client("codebuild")
    build_id = None
    last_err = None
    for _ in range(6):
        try:
            build_id = codebuild.start_build(projectName=project_name)["build"]["id"]
            break
        except Exception as err:  # role propagation lag
            last_err = err
            time.sleep(5)
    assert build_id is not None, f"start_build never succeeded: {last_err}"

    def _get_build() -> dict:
        return codebuild.batch_get_builds(ids=[build_id])["builds"][0]

    progressed = _poll_until(
        _get_build,
        lambda b: b["currentPhase"] not in ("SUBMITTED",) or b["buildComplete"],
        timeout_s=300,
        interval_s=5,
    )
    assert progressed["buildStatus"] in ("IN_PROGRESS", "SUCCEEDED"), progressed

    codebuild.stop_build(id=build_id)
    stopped = _poll_until(
        _get_build,
        lambda b: b["buildComplete"],
        timeout_s=180,
        interval_s=5,
    )
    assert stopped["buildStatus"] == "STOPPED", f"expected STOPPED terminal status, got {stopped}"

    # Independent read through a different operation than the poll above: the
    # stopped build must also surface via ListBuildsForProject, not just BatchGetBuilds.
    listed_ids = codebuild.list_builds_for_project(projectName=project_name)["ids"]
    assert build_id in listed_ids, (
        f"expected {build_id} in ListBuildsForProject({project_name}), got {listed_ids}"
    )


def _deploy_cfn(ctx: Any, template_body: str, parameters: dict) -> dict:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-stack-")

    def _cleanup() -> None:
        cfn.delete_stack(StackName=stack_name)
        waiter = cfn.get_waiter("stack_delete_complete")
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
        Capabilities=["CAPABILITY_IAM"],
        OnFailure="DELETE",
    )
    ctx.on_cleanup(_cleanup)

    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s; last result={result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
