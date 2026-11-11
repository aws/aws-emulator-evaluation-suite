"""deploy-api-mapping-cfn-behaves."""
from __future__ import annotations

import http.client
import urllib.parse
import socket
import ssl
import subprocess
import tempfile
import time
from typing import Any

from behavioral_harness import tags

CHECK = "deploy-api-mapping-cfn-behaves"
GROUP = "state-machine"
SERVICES = ["apigatewayv2", "apigateway"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  DomainNameValue:
    Type: String
  CertArn:
    Type: String
  ApiName:
    Type: String
  UpstreamUrl:
    Type: String
Resources:
  MappedDomainName:
    Type: AWS::ApiGatewayV2::DomainName
    Properties:
      DomainName: !Ref DomainNameValue
      DomainNameConfigurations:
        - EndpointType: REGIONAL
          CertificateArn: !Ref CertArn
          SecurityPolicy: TLS_1_2
  MappedApi:
    Type: AWS::ApiGatewayV2::Api
    Properties:
      Name: !Ref ApiName
      ProtocolType: HTTP
      Target: !Ref UpstreamUrl
      RouteKey: 'ANY /'
  MappedApiMapping:
    Type: AWS::ApiGatewayV2::ApiMapping
    DependsOn:
      - MappedDomainName
      - MappedApi
    Properties:
      DomainName: !Ref DomainNameValue
      ApiId: !Ref MappedApi
      Stage: '$default'
Outputs:
  ApiId:
    Value: !Ref MappedApi
  ApiEndpoint:
    Value: !GetAtt MappedApi.ApiEndpoint
  ApiMappingId:
    Value: !GetAtt MappedApiMapping.ApiMappingId
"""


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:deploy", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed ApiMapping reports its ApiId/Stage via GetApiMapping, and HTTPS
    through the domain's regional endpoint reaches the $default stage's HTTP_PROXY target, a
    REST API MOCK stage the check owns that returns a token unique to this run."""
    domain_name = ctx.unique_name("sim2real-apigwv2-map-") + ".example.com"
    cert_pem, key_pem = _generate_self_signed_cert(ctx, domain_name)
    acm = ctx.client("acm")
    cert_arn = acm.import_certificate(
        Certificate=cert_pem.encode(),
        PrivateKey=key_pem.encode(),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_cert_when_unused(acm, cert_arn))

    api_name = ctx.unique_name("sim2real-apigwv2-mapapi-")
    token = ctx.unique_name("sim2real-behav-upstream-")
    upstream = _mock_backend(ctx, token)

    stack = _deploy_cfn_stack(
        ctx,
        _TEMPLATE,
        parameters={
            "DomainNameValue": domain_name,
            "CertArn": cert_arn,
            "ApiName": api_name,
            "UpstreamUrl": upstream,
        },
    )
    outputs = stack["outputs"]
    api_id = outputs["ApiId"]
    mapping_id = outputs["ApiMappingId"]

    apigwv2 = ctx.client("apigatewayv2")
    fetched = apigwv2.get_api_mapping(ApiMappingId=mapping_id, DomainName=domain_name)
    assert fetched["ApiId"] == api_id, f"expected mapping ApiId {api_id!r}, got {fetched['ApiId']!r}"
    assert fetched["Stage"] == "$default", f"expected mapping Stage '$default', got {fetched['Stage']!r}"

    # The mapping's actual effect is only observable at the domain's own dedicated
    # regional endpoint. Outputs["ApiEndpoint"] is the API's *own* default hostname
    # and would answer identically even if the ApiMapping resource routed nowhere --
    # so the terminal read goes through the domain the mapping names, not the API.
    domain_cfg = _poll_until(
        lambda: apigwv2.get_domain_name(DomainName=domain_name)["DomainNameConfigurations"][0],
        lambda c: c.get("DomainNameStatus") == "AVAILABLE",
        timeout_s=300.0,
        interval_s=10.0,
    )
    gw_host = domain_cfg["ApiGatewayDomainName"]
    unverified_ctx = ssl._create_unverified_context()

    # A real client reaches the mapping by CNAME-ing domain_name at gw_host: DNS
    # resolves to gw_host's address, but the TLS SNI and the Host header the client
    # actually sends still name domain_name -- that pair is what API Gateway's
    # domain-mapping lookup keys on, not the literal regional hostname it happens to
    # be connecting to. Reconstruct that exactly: resolve gw_host's address, then
    # speak TLS/HTTP to it as domain_name.
    def _invoke():
        try:
            raw_sock = socket.create_connection(ctx.endpoint_host(gw_host, 443), timeout=10)
            tls_sock = unverified_ctx.wrap_socket(raw_sock, server_hostname=domain_name)
            _url, _route = ctx.endpoint_route(f"http://{domain_name}")
            _t = urllib.parse.urlsplit(_url)
            conn = http.client.HTTPConnection(_t.hostname, _t.port or 80)
            conn.sock = tls_sock
            conn.request("GET", "/", headers={**({"Host": domain_name}), **_route})
            resp = conn.getresponse()
            status, body = resp.status, resp.read().decode("utf-8", errors="replace")
            conn.close()
            return status, body
        except (OSError, http.client.HTTPException) as exc:
            return None, str(exc)

    status, body = _poll_until(
        _invoke, lambda r: r[0] == 200, timeout_s=150.0, interval_s=5.0
    )
    assert status == 200, f"expected the mapped domain to route to the $default stage with HTTP 200, got {status} ({body!r})"
    assert body == token, f"expected the upstream token {token!r} via the mapped domain, got {body!r}"


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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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


def _mock_backend(ctx, body: str) -> str:
    """The invoke URL of a REST API stage the check owns whose MOCK integration answers GET / with
    200 and ``body``: a backend on the target itself, so the proxy leg never leaves it."""
    ag = ctx.client("apigateway")
    rest_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-backend-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real-check": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: _delete_rest_api(ag, rest_id))
    root = next(r["id"] for r in ag.get_resources(restApiId=rest_id)["items"] if r["path"] == "/")
    ag.put_method(restApiId=rest_id, resourceId=root, httpMethod="GET", authorizationType="NONE")
    ag.put_integration(
        restApiId=rest_id, resourceId=root, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    ag.put_method_response(restApiId=rest_id, resourceId=root, httpMethod="GET", statusCode="200")
    ag.put_integration_response(
        restApiId=rest_id, resourceId=root, httpMethod="GET", statusCode="200",
        selectionPattern="", responseTemplates={"application/json": body},
    )
    ag.create_deployment(restApiId=rest_id, stageName="backend")
    return ctx.rest_api_url(rest_id, "backend")


def _delete_rest_api(ag, api_id, *, budget_s=150.0):
    """DeleteRestApi is throttled hard per account, so retry within a bounded budget and report on
    stderr if the API survives, since teardown exceptions are swallowed."""
    import sys

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + budget_s
    delay = 5.0
    while True:
        try:
            ag.delete_rest_api(restApiId=api_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NotFoundException":
                return
            if code != "TooManyRequestsException" or time.monotonic() >= deadline:
                raise RuntimeError(f"rest api {api_id} not deleted: {code}") from exc
        time.sleep(delay)
        delay = min(delay * 2, 30.0)


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
