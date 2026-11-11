"""e2e-custom-domain-mapping-invoke."""
from __future__ import annotations

import io
import json
import os
import subprocess
import tempfile
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "e2e-custom-domain-mapping-invoke"
GROUP = "e2e"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A custom domain mapped to an HTTP API stage routes real HTTPS invokes to the mapped integration."""
    require_tools("openssl")
    import requests

    apigw = ctx.client("apigatewayv2")
    domain_name = f"{ctx.unique_name('sim2real-behav-dom-').lower()}.example.com"

    backend = _create_http_api_with_lambda_backend(ctx, tag="custom-domain-target", route_key="ANY /hello")

    api = apigw.get_api(ApiId=backend["api_id"])
    default_url, route = ctx.endpoint_route(f"{api['ApiEndpoint']}/{backend['stage']}/hello")
    _poll_http_get(requests, default_url, "custom-domain-target", timeout_s=90.0, headers=route)

    cert_arn = _import_self_signed_cert(ctx, domain_name)

    apigw.create_domain_name(
        DomainName=domain_name,
        DomainNameConfigurations=[{"CertificateArn": cert_arn, "EndpointType": "REGIONAL"}],
        Tags=TAGS,
    )
    ctx.on_cleanup(lambda: apigw.delete_domain_name(DomainName=domain_name))
    gw_host = _wait_domain_available(ctx, domain_name)

    mapping = apigw.create_api_mapping(ApiId=backend["api_id"], DomainName=domain_name, Stage=backend["stage"])
    mapping_id = mapping["ApiMappingId"]
    ctx.on_cleanup(lambda: apigw.delete_api_mapping(ApiMappingId=mapping_id, DomainName=domain_name))

    mappings = apigw.get_api_mappings(DomainName=domain_name)["Items"]
    assert any(m["ApiMappingId"] == mapping_id and m["ApiId"] == backend["api_id"] for m in mappings), (
        f"expected api mapping {mapping_id} for api {backend['api_id']} among {mappings}"
    )

    body = _poll_domain_invoke(ctx, requests, gw_host, domain_name, "/hello", "custom-domain-target", timeout_s=600.0)
    assert "custom-domain-target" in body, (
        f"expected custom-domain invoke of {domain_name}/hello to reach the mapped lambda "
        f"(response should contain 'custom-domain-target'), got {body!r}"
    )


def _self_signed_cert(domain: str) -> tuple[bytes, bytes]:
    with tempfile.TemporaryDirectory() as d:
        key_path = os.path.join(d, "key.pem")
        cert_path = os.path.join(d, "cert.pem")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-days", "365",
                "-nodes", "-keyout", key_path, "-out", cert_path, "-subj", f"/CN={domain}",
            ],
            check=True,
            capture_output=True,
        )
        with open(key_path, "rb") as f:
            key = f.read()
        with open(cert_path, "rb") as f:
            cert = f.read()
    return cert, key


def _import_self_signed_cert(ctx, domain: str) -> str:
    # ACM import needs no domain ownership or DNS validation, unlike request_certificate --
    # the custom domain mapping under test is reachable via the regional target hostname
    # without ever resolving the (unowned) domain_name itself.
    cert, key = _self_signed_cert(domain)
    acm = ctx.client("acm")
    resp = acm.import_certificate(
        Certificate=cert,
        PrivateKey=key,
        Tags=[{"Key": k, "Value": v} for k, v in TAGS.items()],
    )
    arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_certificate_with_retry(acm, arn))
    return arn


def _delete_certificate_with_retry(acm, arn: str, budget_s: float = 300.0) -> None:
    # ACM can still consider the cert "in use" for a while after the domain name that
    # referenced it is deleted; retry that specific transient window, raise anything else.
    deadline = time.monotonic() + budget_s
    delay = 3.0
    while True:
        try:
            acm.delete_certificate(CertificateArn=arn)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(delay)
        delay = min(delay * 2, 30.0)


def _lambda_zip_bytes() -> bytes:
    buf = io.BytesIO()
    src = (
        "import os\n\n"
        "def handler(event, context):\n"
        "    return {'statusCode': 200, 'body': os.environ.get('RESPONSE_TAG', 'default')}\n"
    )
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", src)
    return buf.getvalue()


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": k, "Value": v} for k, v in TAGS.items()],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role["Arn"]


def _wait_lambda_active(ctx, fn_name: str, timeout_s: float = 120.0, interval_s: float = 3.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = lam.get_function_configuration(FunctionName=fn_name).get("State")
        if state == "Active":
            return
        time.sleep(interval_s)
    raise AssertionError(f"lambda function never became Active (last state={state})")


def _create_backend_function(ctx, tag: str) -> tuple[str, str]:
    lam = ctx.client("lambda")
    role_arn = _create_lambda_role(ctx)
    fn_name = ctx.unique_name("sim2real-behav-fn-")
    zip_bytes = _lambda_zip_bytes()
    last_exc: Exception | None = None
    resp = None
    for _ in range(15):
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": zip_bytes},
                Environment={"Variables": {"RESPONSE_TAG": tag}},
                Timeout=10,
                Tags=TAGS,
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_exc = exc
            time.sleep(2.0)
    if resp is None:
        raise AssertionError(f"create_function never succeeded (last_exc={last_exc})")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    _wait_lambda_active(ctx, fn_name)
    return resp["FunctionArn"], fn_name


def _create_http_api_with_lambda_backend(ctx, tag: str, route_key: str) -> dict[str, Any]:
    apigw = ctx.client("apigatewayv2")
    lam = ctx.client("lambda")
    fn_arn, fn_name = _create_backend_function(ctx, tag)

    api_id = apigw.create_api(Name=ctx.unique_name("sim2real-behav-api-"), ProtocolType="HTTP", Tags=TAGS)["ApiId"]
    ctx.on_cleanup(lambda: apigw.delete_api(ApiId=api_id))

    integration_id = apigw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=fn_arn,
        IntegrationMethod="POST",
        PayloadFormatVersion="2.0",
    )["IntegrationId"]
    apigw.create_route(ApiId=api_id, RouteKey=route_key, Target=f"integrations/{integration_id}")

    stage_name = "prod"
    apigw.create_stage(ApiId=api_id, StageName=stage_name, AutoDeploy=True)

    account_id = fn_arn.split(":")[4]
    source_arn = f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/*/*"
    lam.add_permission(
        FunctionName=fn_name,
        StatementId="sim2real-apigw-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=source_arn,
    )
    return {"api_id": api_id, "stage": stage_name}


def _poll_http_get(
    requests_mod, url: str, expected_substring: str, timeout_s: float = 60.0, headers=None, interval_s: float = 3.0
) -> str:
    deadline = time.monotonic() + timeout_s
    last_exc = None
    last_text = None
    while time.monotonic() < deadline:
        try:
            resp = requests_mod.get(url, headers=headers, timeout=10)
            last_text = resp.text
            if resp.status_code == 200 and expected_substring in resp.text:
                return resp.text
        except requests_mod.exceptions.RequestException as exc:
            last_exc = exc
        time.sleep(interval_s)
    raise AssertionError(f"{url} never returned expected content (last_text={last_text!r}, last_exc={last_exc})")


def _wait_domain_available(ctx, domain_name: str, timeout_s: float = 300.0, interval_s: float = 10.0) -> str:
    apigw = ctx.client("apigatewayv2")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        cfg = apigw.get_domain_name(DomainName=domain_name)["DomainNameConfigurations"][0]
        last_status = cfg.get("DomainNameStatus")
        if last_status == "AVAILABLE":
            return cfg["ApiGatewayDomainName"]
        time.sleep(interval_s)
    raise AssertionError(f"domain name never reached AVAILABLE (last status={last_status})")


def _poll_domain_invoke(
    ctx,
    requests_mod,
    gw_host: str,
    domain_name: str,
    path: str,
    expected_substring: str,
    timeout_s: float = 120.0,
    interval_s: float = 10.0,
) -> str:
    # The domain's own regional target hostname already dispatches through this DomainName
    # resource's api mappings -- no DNS control over domain_name is needed.
    url = f"{ctx.endpoint_url(gw_host)}{path}"
    deadline = time.monotonic() + timeout_s
    last_exc = None
    last_text = None
    while time.monotonic() < deadline:
        try:
            resp = requests_mod.get(url, headers={"Host": domain_name}, timeout=15, verify=False)
            last_text = resp.text
            if resp.status_code == 200 and expected_substring in resp.text:
                return resp.text
        except requests_mod.exceptions.RequestException as exc:
            last_exc = exc
        time.sleep(interval_s)
    raise AssertionError(
        f"custom domain invoke of {domain_name}{path} via {url} never returned expected content "
        f"(last_text={last_text!r}, last_exc={last_exc})"
    )


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
