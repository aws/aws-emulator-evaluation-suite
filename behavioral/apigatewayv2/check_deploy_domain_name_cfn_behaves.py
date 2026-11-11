"""deploy-domain-name-cfn-behaves."""
from __future__ import annotations

import subprocess
import tempfile
import time
from typing import Any

from behavioral_harness import tags

CHECK = "deploy-domain-name-cfn-behaves"
GROUP = "state-machine"
SERVICES = ["apigatewayv2"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  DomainNameValue:
    Type: String
  CertArn:
    Type: String
Resources:
  ApiDomainName:
    Type: AWS::ApiGatewayV2::DomainName
    Properties:
      DomainName: !Ref DomainNameValue
      DomainNameConfigurations:
        - EndpointType: REGIONAL
          CertificateArn: !Ref CertArn
          SecurityPolicy: TLS_1_2
Outputs:
  DomainNameArn:
    Value: !GetAtt ApiDomainName.DomainNameArn
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::ApiGatewayV2::DomainName reaches its own AVAILABLE status with
    the template's configuration, and a direct CreateApiMapping can attach a new API to it."""
    domain_name = ctx.unique_name("sim2real-apigwv2-") + ".example.com"
    cert_pem, key_pem = _generate_self_signed_cert(ctx, domain_name)
    acm = ctx.client("acm")
    cert_arn = acm.import_certificate(
        Certificate=cert_pem.encode(),
        PrivateKey=key_pem.encode(),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_cert_when_unused(acm, cert_arn))

    stack = _deploy_cfn_stack(
        ctx,
        _TEMPLATE,
        parameters={"DomainNameValue": domain_name, "CertArn": cert_arn},
    )

    apigwv2 = ctx.client("apigatewayv2")
    got = apigwv2.get_domain_name(DomainName=domain_name)
    configs = got["DomainNameConfigurations"]
    assert len(configs) == 1, configs
    assert configs[0]["CertificateArn"] == cert_arn
    assert configs[0]["EndpointType"] == "REGIONAL"
    assert configs[0]["SecurityPolicy"] == "TLS_1_2"
    assert got["DomainNameArn"] == stack["outputs"]["DomainNameArn"]

    # The CFN resource can report CREATE_COMPLETE before the domain itself leaves
    # the transient state ApiGatewayV2 assigns it -- require the domain's OWN
    # reported status to reach AVAILABLE, not merely accept the stack's word for it.
    final_status = _poll_until(
        lambda: apigwv2.get_domain_name(DomainName=domain_name)["DomainNameConfigurations"][0]["DomainNameStatus"],
        lambda s: s in ("AVAILABLE", "UPDATE_FAILED"),
        timeout_s=180.0,
        interval_s=10.0,
    )
    assert final_status == "AVAILABLE", final_status

    # Beyond "the stack says CREATE_COMPLETE": prove the domain is a real,
    # standalone resource by wiring a brand-new API to it outside CloudFormation.
    api = apigwv2.create_api(
        Name=ctx.unique_name("sim2real-apigwv2-api-"),
        ProtocolType="HTTP",
        Target="https://example.com/",  # never invoked; a reserved documentation host
        RouteKey="ANY /",
        Tags={"sim2real": CHECK},
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: apigwv2.delete_api(ApiId=api_id))

    mapping = apigwv2.create_api_mapping(
        ApiId=api_id, DomainName=domain_name, Stage="$default"
    )
    mapping_id = mapping["ApiMappingId"]
    ctx.on_cleanup(
        lambda: apigwv2.delete_api_mapping(
            ApiMappingId=mapping_id, DomainName=domain_name
        )
    )

    fetched = apigwv2.get_api_mapping(ApiMappingId=mapping_id, DomainName=domain_name)
    assert fetched["ApiId"] == api_id
    assert fetched["Stage"] == "$default"


def _generate_self_signed_cert(ctx, common_name: str) -> tuple[str, str]:
    """Mint a self-signed cert for ACM ImportCertificate: it is ISSUED immediately, as
    CreateDomainName requires; a DNS-validated request never issues for a domain we don't own."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    with tempfile.TemporaryDirectory() as td:
        key_path = f"{td}/key.pem"
        cert_path = f"{td}/cert.pem"
        cmd = [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_path, "-out", cert_path,
            "-days", "30", "-nodes", "-subj", f"/CN={common_name}",
        ]
        subprocess.run(
            cmd, check=True, capture_output=True, env=ctx.subprocess_env(), timeout=30
        )
        with open(cert_path) as fh:
            cert_pem = fh.read()
        with open(key_path) as fh:
            key_pem = fh.read()
    return cert_pem, key_pem


def _deploy_cfn_stack(
    ctx, template_body: str, parameters: dict[str, str] | None = None, timeout_s: float = 600.0
) -> dict[str, Any]:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-apigwv2-stack-")
    params = [{"ParameterKey": k, "ParameterValue": v} for k, v in (parameters or {}).items()]

    def _cleanup() -> None:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=params,
        OnFailure="DELETE",
    )
    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name,
        WaiterConfig={"Delay": 2, "MaxAttempts": max(1, int(timeout_s // 2))},
    )
    resp = cfn.describe_stacks(StackName=stack_name)
    outputs = {o["OutputKey"]: o["OutputValue"] for o in resp["Stacks"][0].get("Outputs", [])}
    return {"stack_name": stack_name, "outputs": outputs}


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _delete_cert_when_unused(acm, cert_arn: str, budget_s: float = 300.0) -> None:
    """DeleteCertificate answers ResourceInUseException for a window after the custom domain name
    that referenced it is deleted, while ACM propagates the disassociation; retry through that
    window instead of leaking the cert."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + budget_s
    delay = 5.0
    while True:
        try:
            acm.delete_certificate(CertificateArn=cert_arn)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(delay)
        delay = min(delay * 2, 30.0)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
