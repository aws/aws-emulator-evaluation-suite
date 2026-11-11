"""deploy-domain-name-basepathmapping-cfn-resolves."""
from __future__ import annotations

import os
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-domain-name-basepathmapping-cfn-resolves"
GROUP = "state-machine"
SERVICES = ["apigateway"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  DomainNameParam:
    Type: String
  CertificateArnParam:
    Type: String
Resources:
  Api:
    Type: AWS::ApiGateway::RestApi
    Properties:
      Name: !Sub '${AWS::StackName}-api'
  EchoResource:
    Type: AWS::ApiGateway::Resource
    Properties:
      RestApiId: !Ref Api
      ParentId: !GetAtt Api.RootResourceId
      PathPart: echo
  EchoMethod:
    Type: AWS::ApiGateway::Method
    Properties:
      RestApiId: !Ref Api
      ResourceId: !Ref EchoResource
      HttpMethod: GET
      AuthorizationType: NONE
      Integration:
        Type: MOCK
        RequestTemplates:
          application/json: '{"statusCode": 200}'
        IntegrationResponses:
          - StatusCode: '200'
            ResponseTemplates:
              application/json: '{"message": "ok"}'
      MethodResponses:
        - StatusCode: '200'
  ApiDeployment:
    Type: AWS::ApiGateway::Deployment
    DependsOn: EchoMethod
    Properties:
      RestApiId: !Ref Api
  ApiStage:
    Type: AWS::ApiGateway::Stage
    Properties:
      RestApiId: !Ref Api
      DeploymentId: !Ref ApiDeployment
      StageName: sim2real
  ApiDomainName:
    Type: AWS::ApiGateway::DomainName
    Properties:
      DomainName: !Ref DomainNameParam
      RegionalCertificateArn: !Ref CertificateArnParam
      EndpointConfiguration:
        Types:
          - REGIONAL
  ApiBasePathMapping:
    Type: AWS::ApiGateway::BasePathMapping
    DependsOn:
      - ApiStage
      - ApiDomainName
    Properties:
      DomainName: !Ref ApiDomainName
      RestApiId: !Ref Api
      Stage: !Ref ApiStage
      BasePath: v1
Outputs:
  RestApiId:
    Value: !Ref Api
  StageName:
    Value: !Ref ApiStage
  DomainNameOut:
    Value: !Ref ApiDomainName
"""


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation DomainName+BasePathMapping stack reaches AVAILABLE and GetBasePathMapping
    resolves to the stack's RestApi/stage; deleting the stack removes both from API Gateway."""
    domain = f"{ctx.unique_name('agw-domain-')}.example.com"
    cert_bytes, key_bytes = _generate_self_signed_cert(domain)

    acm = ctx.client("acm")
    cert_arn = acm.import_certificate(
        Certificate=cert_bytes,
        PrivateKey=key_bytes,
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=cert_arn))

    stack_name, outputs = _deploy_stack(
        ctx,
        _TEMPLATE,
        parameters={"DomainNameParam": domain, "CertificateArnParam": cert_arn},
    )

    apigw = ctx.client("apigateway")
    _wait_domain_available(ctx, domain)

    mapping = apigw.get_base_path_mapping(domainName=domain, basePath="v1")
    assert mapping["restApiId"] == outputs["RestApiId"], (
        f"expected the basePathMapping to resolve to restApiId="
        f"{outputs['RestApiId']!r}, got {mapping['restApiId']!r}"
    )
    assert mapping["stage"] == outputs["StageName"], (
        f"expected the basePathMapping to resolve to stage="
        f"{outputs['StageName']!r}, got {mapping['stage']!r}"
    )

    # The stack's delete cascade must actually remove the domain and its mapping
    # from apigateway's own state, not merely report DELETE_COMPLETE.
    _delete_stack(ctx, stack_name)
    _poll_until_not_found(
        lambda: apigw.get_base_path_mapping(domainName=domain, basePath="v1"),
        description="the deleted stack's basePathMapping",
    )
    _poll_until_not_found(
        lambda: apigw.get_domain_name(domainName=domain),
        description="the deleted stack's domain name",
    )


def _generate_self_signed_cert(domain: str) -> tuple[bytes, bytes]:
    from fidelity_tests_runner import require_tools

    require_tools("openssl")
    with tempfile.TemporaryDirectory() as tmp_dir:
        key_path = os.path.join(tmp_dir, "key.pem")
        cert_path = os.path.join(tmp_dir, "cert.pem")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key_path, "-out", cert_path,
                "-days", "2", "-nodes", "-subj", f"/CN={domain}",
            ],
            check=True, capture_output=True,
        )
        with open(key_path, "rb") as f:
            key_bytes = f.read()
        with open(cert_path, "rb") as f:
            cert_bytes = f.read()
    return cert_bytes, key_bytes


def _wait_domain_available(ctx, domain: str, timeout_s: float = 180.0, interval_s: float = 5.0) -> dict:
    apigw = ctx.client("apigateway")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = apigw.get_domain_name(domainName=domain)
        last_status = resp.get("domainNameStatus")
        if last_status == "AVAILABLE":
            return resp
        if last_status == "FAILED":
            raise AssertionError(f"domain {domain} entered FAILED: {resp.get('domainNameStatusMessage')}")
        time.sleep(interval_s)
    raise AssertionError(f"domain {domain} did not become AVAILABLE within {timeout_s}s (last={last_status})")


def _poll_until_not_found(fn, timeout_s: float = 30.0, interval_s: float = 2.0, description: str = "resource") -> None:
    """Poll fn() until it raises NotFoundException (removal can lag the delete); any other
    error code, or no not-found within the bound, fails."""
    deadline = time.monotonic() + timeout_s
    last = "still present"
    while time.monotonic() < deadline:
        try:
            fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NotFoundException":
                return
            last = code
        else:
            last = "call unexpectedly succeeded (resource still exists)"
        time.sleep(interval_s)
    raise AssertionError(f"expected {description} to read as NotFoundException within {timeout_s}s, last saw: {last}")


def _deploy_stack(ctx, template_body: str, parameters: dict | None = None):
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-agw-")
    kwargs = {
        "StackName": stack_name,
        "TemplateBody": template_body,
        "Capabilities": ["CAPABILITY_IAM"],
        "Tags": [{"Key": "sim2real-behav", "Value": CHECK}],
    }
    if parameters:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    cfn.create_stack(**kwargs)
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    _wait_for_stack(ctx, stack_name, {"CREATE_COMPLETE"}, {"CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"})
    stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stacks[0].get("Outputs", [])}
    return stack_name, outputs


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    _wait_for_stack(ctx, stack_name, {"DELETE_COMPLETE"}, set(), missing_ok=True)


def _wait_for_stack(
    ctx,
    stack_name: str,
    ok_statuses: set,
    bad_statuses: set,
    missing_ok: bool = False,
    timeout_s: float = 420.0,
    interval_s: float = 6.0,
) -> None:
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as exc:
            if missing_ok and "does not exist" in str(exc):
                return
            raise
        if not stacks:
            if missing_ok:
                return
            raise AssertionError(f"stack {stack_name} vanished unexpectedly")
        last_status = stacks[0]["StackStatus"]
        if last_status in ok_statuses:
            return
        if last_status in bad_statuses:
            raise AssertionError(f"stack {stack_name} entered {last_status}")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not settle within {timeout_s}s (last={last_status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
