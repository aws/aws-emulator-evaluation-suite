"""deploy-custom-domain-cfn-mapping-active."""
from __future__ import annotations

import datetime
import os
import subprocess
import tempfile
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "deploy-custom-domain-cfn-mapping-active"
GROUP = "state-machine"
SERVICES = ["apigateway"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  ApiName:
    Type: String
  DomainName:
    Type: String
  CertificateArn:
    Type: String
Resources:
  RestApi:
    Type: AWS::ApiGateway::RestApi
    Properties:
      Name: !Ref ApiName
  RootMethod:
    Type: AWS::ApiGateway::Method
    Properties:
      RestApiId: !Ref RestApi
      ResourceId: !GetAtt RestApi.RootResourceId
      HttpMethod: GET
      AuthorizationType: NONE
      Integration:
        Type: MOCK
        RequestTemplates:
          application/json: '{"statusCode": 200}'
        IntegrationResponses:
          - StatusCode: "200"
      MethodResponses:
        - StatusCode: "200"
  ApiDeployment:
    Type: AWS::ApiGateway::Deployment
    DependsOn: RootMethod
    Properties:
      RestApiId: !Ref RestApi
  ApiStage:
    Type: AWS::ApiGateway::Stage
    Properties:
      RestApiId: !Ref RestApi
      DeploymentId: !Ref ApiDeployment
      StageName: prod
  CustomDomain:
    Type: AWS::ApiGateway::DomainName
    Properties:
      DomainName: !Ref DomainName
      RegionalCertificateArn: !Ref CertificateArn
      EndpointConfiguration:
        Types:
          - REGIONAL
  BasePathMap:
    Type: AWS::ApiGateway::BasePathMapping
    DependsOn: CustomDomain
    Properties:
      DomainName: !Ref DomainName
      RestApiId: !Ref RestApi
      Stage: !Ref ApiStage
      BasePath: v1
Outputs:
  RestApiId:
    Value: !Ref RestApi
  StageName:
    Value: !Ref ApiStage
"""


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-provisioned DomainName reaches AVAILABLE and its BasePathMapping points at the
    templated RestApi/stage; deleting the stack removes both from the control plane."""
    domain_name = f"{ctx.unique_name('sim2real-domain-')}.example.com"
    cert_pem, key_pem = _generate_self_signed_cert(domain_name)

    acm = ctx.client("acm")
    cert_arn = acm.import_certificate(
        Certificate=cert_pem,
        PrivateKey=key_pem,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_certificate(acm, cert_arn))

    stack_name, outputs = _deploy_cfn(
        ctx,
        _TEMPLATE,
        parameters={
            "ApiName": ctx.unique_name("sim2real-domain-api-"),
            "DomainName": domain_name,
            "CertificateArn": cert_arn,
        },
    )
    rest_api_id = outputs["RestApiId"]
    stage_name = outputs["StageName"]

    apigw = ctx.client("apigateway")
    status = _poll_domain_available(apigw, domain_name, timeout_s=300)
    assert status == "AVAILABLE", f"domainNameStatus never reached AVAILABLE, last={status}"

    mapping = apigw.get_base_path_mapping(domainName=domain_name, basePath="v1")
    assert mapping["restApiId"] == rest_api_id, f"expected restApiId={rest_api_id}, got {mapping}"
    assert mapping["stage"] == stage_name, f"expected stage={stage_name}, got {mapping}"

    _delete_stack(ctx, stack_name)

    domain_not_found = ("NotFoundException", "Invalid domain name identifier specified")
    domain_gone = _error(lambda: apigw.get_domain_name(domainName=domain_name))
    assert domain_gone == domain_not_found, (
        f"deleting the stack must remove the CFN-owned custom domain from the control "
        f"plane, not just from the template; expected {domain_not_found!r} from "
        f"GetDomainName, got {domain_gone!r}"
    )
    # With the domain gone, GetBasePathMapping is refused at the domain lookup.
    mapping_gone = _error(lambda: apigw.get_base_path_mapping(domainName=domain_name, basePath="v1"))
    assert mapping_gone == domain_not_found, (
        f"deleting the stack must remove the base path mapping too; expected "
        f"{domain_not_found!r} from GetBasePathMapping, got {mapping_gone!r}"
    )


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
            time.sleep(10)


def _generate_self_signed_cert(domain: str) -> tuple[bytes, bytes]:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError:
        return _generate_self_signed_cert_openssl(domain)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return cert_pem, key_pem


def _generate_self_signed_cert_openssl(domain: str) -> tuple[bytes, bytes]:
    require_tools("openssl")
    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = os.path.join(tmpdir, "key.pem")
        cert_path = os.path.join(tmpdir, "cert.pem")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
                "-keyout", key_path, "-out", cert_path, "-days", "365",
                "-subj", f"/CN={domain}",
            ],
            check=True,
            capture_output=True,
        )
        with open(key_path, "rb") as f:
            key_pem = f.read()
        with open(cert_path, "rb") as f:
            cert_pem = f.read()
        return cert_pem, key_pem


def _deploy_cfn(
    ctx: Any, template_body: str, parameters: dict[str, str] | None = None
) -> tuple[str, dict[str, str]]:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-domain-stack-")
    params = [
        {"ParameterKey": k, "ParameterValue": v} for k, v in (parameters or {}).items()
    ]

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=params,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))

    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}
    return stack_name, outputs


def _delete_stack(ctx: Any, stack_name: str) -> None:
    from botocore.exceptions import ClientError

    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack_name)
        waiter = cfn.get_waiter("stack_delete_complete")
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    except ClientError as err:
        if "does not exist" not in str(err):
            raise


def _error(fn):
    """Call fn(); return its (Error.Code, Error.Message). A call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_domain_available(apigw: Any, domain_name: str, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = apigw.get_domain_name(domainName=domain_name)["domainNameStatus"]
        if status in ("AVAILABLE", "FAILED"):
            return status
        time.sleep(2)
    return status


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
