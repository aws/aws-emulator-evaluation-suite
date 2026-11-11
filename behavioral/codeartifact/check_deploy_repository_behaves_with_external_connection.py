"""deploy-repository-behaves-with-external-connection."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "deploy-repository-behaves-with-external-connection"
GROUP = "state-machine"
SERVICES = ["codeartifact"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  DomainNameParam:
    Type: String
  RepositoryNameParam:
    Type: String
Resources:
  Domain:
    Type: AWS::CodeArtifact::Domain
    Properties:
      DomainName: !Ref DomainNameParam
  Repository:
    Type: AWS::CodeArtifact::Repository
    DependsOn: Domain
    Properties:
      DomainName: !Ref DomainNameParam
      RepositoryName: !Ref RepositoryNameParam
Outputs:
  RepositoryName:
    Value: !GetAtt Repository.Name
  RepositoryArn:
    Value: !GetAtt Repository.Arn
"""


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed repository accepts an external connection via the API.

    GetRepositoryEndpoint returns an HTTPS URL naming the domain and repository, and
    public:npmjs persists on an independent DescribeRepository.
    """
    ca = ctx.client("codeartifact")
    domain_name = ctx.unique_name("sim2real-behav-cfndom-")
    repo_name = ctx.unique_name("sim2real-behav-cfnrepo-")

    stack_name, outputs = _deploy_cfn(
        ctx,
        _TEMPLATE,
        {"DomainNameParam": domain_name, "RepositoryNameParam": repo_name},
    )
    assert outputs["RepositoryName"] == repo_name, (
        f"CFN stack output RepositoryName was {outputs['RepositoryName']!r}, "
        f"expected {repo_name!r}"
    )

    endpoint = ca.get_repository_endpoint(
        domain=domain_name, repository=repo_name, format="npm"
    )["repositoryEndpoint"]
    assert endpoint.startswith("https://"), f"repository endpoint {endpoint!r} is not HTTPS"
    assert domain_name in endpoint, f"domain {domain_name!r} not present in endpoint {endpoint!r}"
    assert repo_name in endpoint, f"repository {repo_name!r} not present in endpoint {endpoint!r}"

    updated = ca.associate_external_connection(
        domain=domain_name, repository=repo_name, externalConnection="public:npmjs"
    )["repository"]
    connection_names = {c["externalConnectionName"] for c in updated["externalConnections"]}
    assert connection_names == {"public:npmjs"}, (
        f"associate_external_connection response reported {connection_names!r}, "
        f"expected {{'public:npmjs'}}"
    )

    described = ca.describe_repository(domain=domain_name, repository=repo_name)["repository"]
    described_names = {c["externalConnectionName"] for c in described["externalConnections"]}
    assert described_names == {"public:npmjs"}, (
        f"describe_repository (independent read) reported external connections "
        f"{described_names!r}, expected {{'public:npmjs'}} to have persisted"
    )


def _deploy_cfn(ctx, template_body: str, params: dict[str, str]) -> tuple[str, dict[str, str]]:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in params.items()],
        OnFailure="DELETE",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
