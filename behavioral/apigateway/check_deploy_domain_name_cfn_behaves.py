"""deploy-domain-name-cfn-behaves."""
from __future__ import annotations

import json
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-domain-name-cfn-behaves"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A DomainName + BasePathMapping deployed via CloudFormation resolves the base
    path back to the correct underlying REST API and stage through GetBasePathMapping,
    and the domain eventually reaches an AVAILABLE status."""
    domain_name = f"{ctx.unique_name('sim2real-apigw-dn-')}.example.com".lower()
    cert_pem, key_pem = _generate_self_signed_cert(domain_name)

    acm = ctx.client("acm")
    cert_arn = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem)["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_certificate(acm, cert_arn))

    api_name = ctx.unique_name("sim2real-apigw-domapi-")
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "RestApi": {
                "Type": "AWS::ApiGateway::RestApi",
                "Properties": {"Name": api_name},
            },
            "HelloResource": {
                "Type": "AWS::ApiGateway::Resource",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "ParentId": {"Fn::GetAtt": ["RestApi", "RootResourceId"]},
                    "PathPart": "hello",
                },
            },
            "GetMethod": {
                "Type": "AWS::ApiGateway::Method",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "ResourceId": {"Ref": "HelloResource"},
                    "HttpMethod": "GET",
                    "AuthorizationType": "NONE",
                    "Integration": {
                        "Type": "MOCK",
                        "RequestTemplates": {"application/json": '{"statusCode": 200}'},
                        "IntegrationResponses": [{"StatusCode": "200"}],
                    },
                    "MethodResponses": [{"StatusCode": "200"}],
                },
            },
            "ApiDeployment": {
                "Type": "AWS::ApiGateway::Deployment",
                "DependsOn": "GetMethod",
                "Properties": {"RestApiId": {"Ref": "RestApi"}},
            },
            "ProdStage": {
                "Type": "AWS::ApiGateway::Stage",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "DeploymentId": {"Ref": "ApiDeployment"},
                    "StageName": "prod",
                },
            },
            "CustomDomain": {
                "Type": "AWS::ApiGateway::DomainName",
                "Properties": {
                    "DomainName": domain_name,
                    "RegionalCertificateArn": cert_arn,
                    "EndpointConfiguration": {"Types": ["REGIONAL"]},
                },
            },
            "BasePathMapping": {
                "Type": "AWS::ApiGateway::BasePathMapping",
                "DependsOn": "ProdStage",
                "Properties": {
                    "DomainName": {"Ref": "CustomDomain"},
                    "RestApiId": {"Ref": "RestApi"},
                    "Stage": {"Ref": "ProdStage"},
                    "BasePath": "v1",
                },
            },
        },
        "Outputs": {
            "RestApiId": {"Value": {"Ref": "RestApi"}},
            "DomainName": {"Value": {"Ref": "CustomDomain"}},
        },
    }

    outputs = _deploy_cfn_stack(ctx, json.dumps(template))
    apigw = ctx.client("apigateway")

    mapping = apigw.get_base_path_mapping(domainName=outputs["DomainName"], basePath="v1")
    assert mapping["restApiId"] == outputs["RestApiId"], (
        f"expected basePathMapping.restApiId={outputs['RestApiId']!r}, got {mapping['restApiId']!r}"
    )
    assert mapping["stage"] == "prod", f"expected basePathMapping.stage='prod', got {mapping['stage']!r}"

    status = _poll_until(
        lambda: apigw.get_domain_name(domainName=outputs["DomainName"])["domainNameStatus"],
        lambda s: s in ("AVAILABLE", "FAILED"),
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert status == "AVAILABLE", f"domain never became AVAILABLE, ended in {status}"


def _delete_certificate(acm, cert_arn: str) -> None:
    """Teardown: the certificate stays in use until the domain-name deletion settles."""
    deadline = time.monotonic() + 300
    while True:
        try:
            acm.delete_certificate(CertificateArn=cert_arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _generate_self_signed_cert(domain: str) -> tuple[bytes, bytes]:
    from fidelity_tests_runner import require_tools

    require_tools("openssl")
    with tempfile.TemporaryDirectory() as tmp_dir:
        key_path = f"{tmp_dir}/key.pem"
        cert_path = f"{tmp_dir}/cert.pem"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key_path, "-out", cert_path,
                "-days", "2", "-nodes", "-subj", f"/CN={domain}",
            ],
            check=True, capture_output=True,
        )
        with open(key_path, "rb") as f:
            key_pem = f.read()
        with open(cert_path, "rb") as f:
            cert_pem = f.read()
    return cert_pem, key_pem


def _deploy_cfn_stack(ctx, template_body: str) -> dict:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-apigw-cfn-")

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        waiter = cfn.get_waiter("stack_delete_complete")
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Capabilities=["CAPABILITY_IAM"],
    )
    ctx.on_cleanup(_cleanup)
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
