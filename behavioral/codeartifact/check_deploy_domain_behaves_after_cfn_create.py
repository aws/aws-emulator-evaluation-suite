"""deploy-domain-behaves-after-cfn-create."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-domain-behaves-after-cfn-create"
GROUP = "state-machine"
SERVICES = ["codeartifact"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  DomainNameParam:
    Type: String
Resources:
  Domain:
    Type: AWS::CodeArtifact::Domain
    Properties:
      DomainName: !Ref DomainNameParam
      Tags:
        - Key: sim2real
          Value: deploy-domain-behaves-after-cfn-create
Outputs:
  DomainName:
    Value: !GetAtt Domain.Name
  DomainArn:
    Value: !GetAtt Domain.Arn
"""


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::CodeArtifact::Domain is truly active: it is
    describable through the CodeArtifact API directly (not just CREATE_COMPLETE in
    CloudFormation) and it can host a newly created repository."""
    ca = ctx.client("codeartifact")
    domain_name = ctx.unique_name("sim2real-behav-cfndom-")

    stack_name, outputs = _deploy_cfn(
        ctx, _TEMPLATE, {"DomainNameParam": domain_name}
    )
    assert outputs["DomainName"] == domain_name

    described = ca.describe_domain(domain=domain_name)["domain"]
    assert described["status"] == "Active"
    assert described["arn"] == outputs["DomainArn"]

    repo = ctx.unique_name("sim2real-behav-repo-")
    ca.create_repository(
        domain=domain_name, repository=repo, tags=[{"key": "sim2real", "value": CHECK}]
    )
    ctx.on_cleanup(lambda: _delete_repository(ca, domain_name, repo))

    repo_described = ca.describe_repository(domain=domain_name, repository=repo)["repository"]
    assert repo_described["domainName"] == domain_name
    assert repo_described["name"] == repo


def _delete_repository(ca, domain_name: str, repo: str) -> None:
    """Teardown: delete the repository, tolerating only its not-found."""
    try:
        ca.delete_repository(domain=domain_name, repository=repo)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _deploy_cfn(ctx, template_body: str, params: dict[str, str]) -> tuple[str, dict[str, str]]:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in params.items()],
        OnFailure="DELETE",
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stacks[0].get("Outputs", [])}
    return stack_name, outputs


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    waiter = cfn.get_waiter("stack_delete_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
