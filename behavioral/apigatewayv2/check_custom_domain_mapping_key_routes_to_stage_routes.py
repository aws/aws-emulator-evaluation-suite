"""custom-domain-mapping-key-routes-to-stage-routes."""
from __future__ import annotations

import io
import json
import socket
import ssl
import time
import zipfile
from urllib.parse import urlsplit

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "custom-domain-mapping-key-routes-to-stage-routes"
GROUP = 'custom-domain'
SERVICES = ['apigatewayv2']

DOMAIN_WAIT_S = 420
CERT_RELEASE_WAIT_S = 420

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
TAGS_KV = [{"Key": k, "Value": v} for k, v in TAGS.items()]

_EVENT_ECHO_CODE = """
import json
def lambda_handler(event, context):
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(event),
    }
"""


def _create_lambda_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-lambda-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=TAGS_KV,
    )["Role"]["Arn"]

    def _cleanup_role():
        for pn in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pn)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup_role)
    return arn


def _delete_lambda_log_group(ctx, function_name):
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _create_lambda(ctx, handler_code):
    """Create a python Lambda; return {name, arn}. Registers teardown."""
    role_arn = _create_lambda_role(ctx)
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-fn-")
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    kwargs = {
        "FunctionName": name,
        "Runtime": "python3.12",
        "Role": role_arn,
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": zip_buf.getvalue()},
        "Timeout": 10,
        "MemorySize": 128,
        "Tags": dict(TAGS),
    }
    ctx.on_cleanup(lambda: _delete_lambda_log_group(ctx, name))
    deadline = time.monotonic() + 60
    while True:
        try:
            arn = lam.create_function(**kwargs)["FunctionArn"]
            break
        except ClientError as e:
            # IAM propagation: a freshly created role is not yet assumable by Lambda.
            if "cannot be assumed" in str(e) and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    deadline = time.monotonic() + 60
    while True:
        state = lam.get_function_configuration(FunctionName=name).get("State")
        if state == "Active":
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"lambda {name} did not become Active within 60s (last {state!r})")
        time.sleep(2.0)
    return {"name": name, "arn": arn}


def _allow_apigw_invoke(ctx, fn_name, api_id):
    ctx.client("lambda").add_permission(
        FunctionName=fn_name,
        StatementId="apigw-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{ctx.account}:{api_id}/*/*",
    )


def _create_http_api(ctx, **extra):
    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-httpapi-"), ProtocolType="HTTP", Tags=TAGS, **extra
    )
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api["ApiId"]))
    return api["ApiId"], api["ApiEndpoint"]



def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed value={last!r}")


def _self_signed_cert(domain):
    import os as _os
    import subprocess
    import tempfile

    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    with tempfile.TemporaryDirectory() as d:
        key_path = _os.path.join(d, "key.pem")
        cert_path = _os.path.join(d, "cert.pem")
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


def _delete_cert_when_unused(acm, cert_arn):
    """DeleteCertificate is ResourceInUseException for minutes after the domain that used it is
    deleted, while ACM propagates the disassociation; poll through that window."""
    deadline = time.monotonic() + CERT_RELEASE_WAIT_S
    while True:
        try:
            acm.delete_certificate(CertificateArn=cert_arn)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(10)


def _import_self_signed_cert(ctx, domain):
    cert, key = _self_signed_cert(domain)
    acm = ctx.client("acm")
    arn = acm.import_certificate(Certificate=cert, PrivateKey=key, Tags=TAGS_KV)["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_cert_when_unused(acm, arn))
    return arn


def _get_on_domain(invoke_url, domain, path, timeout=15.0):
    """(status, body) of one GET to the invoke URL's host with ``domain`` as SNI and Host, or None
    when no server answered. Redirects are not followed; the self-signed cert is not verified."""
    url = urlsplit(invoke_url)
    secure = url.scheme == "https"
    port = url.port or (443 if secure else 80)
    try:
        conn = socket.create_connection((url.hostname, port), timeout=timeout)
    except OSError:
        return None
    request = f"GET {path} HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n".encode()
    try:
        if secure:
            conn = ssl._create_unverified_context().wrap_socket(conn, server_hostname=domain)
        with conn:
            conn.settimeout(timeout)
            conn.sendall(request)
            data = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
    except (OSError, ssl.SSLError):
        return None
    head, _, body = data.partition(b"\r\n\r\n")
    parts = head.split(b"\r\n", 1)[0].split(b" ")
    if len(parts) < 2 or not parts[1].isdigit():
        return None
    if b"transfer-encoding: chunked" in head.lower():
        out, rest = b"", body
        while rest:
            size_line, _, rest = rest.partition(b"\r\n")
            size = int(size_line.split(b";")[0] or b"0", 16)
            if size == 0:
                break
            out, rest = out + rest[:size], rest[size + 2:]
        body = out
    return int(parts[1]), body.decode(errors="replace")


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A custom domain's ApiMappingKey ``v1`` is a path prefix: /v1/items reaches the stage's
    GET /items route with the domain, stage and rawPath /prod/items in the event; /items is a 403.
    """
    agw = ctx.client("apigatewayv2")
    fn = _create_lambda(ctx, _EVENT_ECHO_CODE)
    api_id, api_endpoint = _create_http_api(ctx)
    integ_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=fn["arn"],
        IntegrationMethod="POST",
        PayloadFormatVersion="2.0",
    )["IntegrationId"]
    agw.create_route(ApiId=api_id, RouteKey="GET /items", Target=f"integrations/{integ_id}")
    _allow_apigw_invoke(ctx, fn["name"], api_id)
    agw.create_stage(ApiId=api_id, StageName="prod", AutoDeploy=True, Tags=TAGS)
    ctx.on_cleanup(lambda: agw.delete_stage(ApiId=api_id, StageName="prod"))

    domain = ctx.unique_name("sim2real-behav-") + ".sim2real-test.internal"
    cert_arn = _import_self_signed_cert(ctx, domain)
    agw.create_domain_name(
        DomainName=domain,
        DomainNameConfigurations=[{"CertificateArn": cert_arn, "EndpointType": "REGIONAL"}],
        Tags=TAGS,
    )
    ctx.on_cleanup(lambda: agw.delete_domain_name(DomainName=domain))
    mapping_id = agw.create_api_mapping(
        ApiId=api_id, DomainName=domain, Stage="prod", ApiMappingKey="v1"
    )["ApiMappingId"]
    ctx.on_cleanup(lambda: agw.delete_api_mapping(ApiMappingId=mapping_id, DomainName=domain))

    # The domain is not publicly delegated, so requests go to the invoke URL's host with SNI/Host.
    invoke_url = ctx.stage_url(api_endpoint, "prod")
    _poll_until(
        lambda: agw.get_domain_name(DomainName=domain)["DomainNameConfigurations"][0],
        lambda c: c.get("DomainNameStatus") == "AVAILABLE",
        timeout_s=DOMAIN_WAIT_S,
        interval_s=10,
    )
    mappings = agw.get_api_mappings(DomainName=domain)["Items"]
    listed = [(m["ApiId"], m["Stage"], m["ApiMappingKey"]) for m in mappings]
    assert listed == [(api_id, "prod", "v1")], (
        f"GetApiMappings must list exactly the v1 -> prod mapping, got "
        f"{[(m.get('Stage'), m.get('ApiMappingKey')) for m in mappings]!r}"
    )

    got = _poll_until(
        lambda: _get_on_domain(invoke_url, domain, "/v1/items"),
        lambda r: r is not None and r[0] == 200,
        timeout_s=180,
    )
    ev = json.loads(got[1])
    assert ev.get("routeKey") == "GET /items", (
        f"the mapping key must be consumed before route matching; routeKey was {ev.get('routeKey')!r}"
    )
    rc = ev.get("requestContext") or {}
    assert rc.get("domainName") == domain, (
        f"requestContext.domainName must be the custom domain, got a value of length "
        f"{len(str(rc.get('domainName')))}"
    )
    assert rc.get("stage") == "prod", f"requestContext.stage expected 'prod', got {rc.get('stage')!r}"
    # The mapping key is stripped and replaced by the MAPPED STAGE's name: the backend sees the
    # same rawPath it would on the stage's own execute-api URL, never the client's path.
    assert ev.get("rawPath") == "/prod/items", (
        f"rawPath through the custom domain expected '/prod/items' (mapping key 'v1' stripped, "
        f"stage prefix present), got {ev.get('rawPath')!r}"
    )

    status, body = _get_on_domain(invoke_url, domain, "/items") or (None, "")
    assert status == 403, f"a path outside the mapping key expected 403, got {status}: {body[:300]!r}"
    assert json.loads(body) == {"message": "Forbidden"}, f"unexpected body {body[:300]!r}"
    assert "routeKey" not in body, "a path outside the mapping key reached the backend"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
