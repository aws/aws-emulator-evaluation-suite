"""deploy-ecr-repository-lifecycle-then-not-found."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ecr-repository-lifecycle-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "ecr"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only the resource's own
    not_found codes mean it is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::ECR::Repository is readable through ECR's own API with the
    template's properties and the stack's Fn::GetAtt outputs, and deleting the stack removes it:
    DescribeRepositories then raises RepositoryNotFoundException naming the repository and registry.
    """
    cfn = ctx.client("cloudformation")
    ecr = ctx.client("ecr")
    repo_name = ctx.unique_name("sim2real-behav-ecr-")
    stack_name = ctx.unique_name("sim2real-behav-ecr-stack-")
    template = json.dumps({
        "Resources": {
            "Repo": {
                "Type": "AWS::ECR::Repository",
                "Properties": {
                    "RepositoryName": repo_name,
                    "ImageTagMutability": "IMMUTABLE",
                },
            }
        },
        "Outputs": {
            "RepoArn": {"Value": {"Fn::GetAtt": ["Repo", "Arn"]}},
            "RepoUri": {"Value": {"Fn::GetAtt": ["Repo", "RepositoryUri"]}},
        },
    })

    cfn.create_stack(StackName=stack_name, TemplateBody=template,
                      Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(_teardown(lambda: _delete_stack(cfn, stack_name), "ValidationError"))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])
    }

    described = ecr.describe_repositories(repositoryNames=[repo_name])["repositories"][0]
    assert described["imageTagMutability"] == "IMMUTABLE", (
        f"expected imageTagMutability IMMUTABLE, got {described['imageTagMutability']!r}"
    )
    assert outputs["RepoArn"] == described["repositoryArn"], (
        f"GetAtt Arn {outputs['RepoArn']!r} must match ECR's own Arn {described['repositoryArn']!r}"
    )
    assert outputs["RepoUri"] == described["repositoryUri"], (
        f"GetAtt RepositoryUri {outputs['RepoUri']!r} must match ECR's own "
        f"{described['repositoryUri']!r}"
    )

    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    code, message = _error(lambda: ecr.describe_repositories(repositoryNames=[repo_name]))
    expected_message = (
        f"The repository with name '{repo_name}' does not exist in the registry "
        f"with id '{ctx.account}'"
    )
    assert code == "RepositoryNotFoundException", (
        f"expected RepositoryNotFoundException after stack delete, got {code!r}"
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _delete_stack(cfn, stack_name: str) -> None:
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
