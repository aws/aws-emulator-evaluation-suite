"""microvm-auth-token-grants-endpoint-access."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "microvm-auth-token-grants-endpoint-access"
GROUP = "native-protocol"
SERVICES = ["lambda-microvms"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CreateMicrovmAuthToken token for port 8080 reaches the guest app via the endpoint; a
    token scoped to another port gets 403 on 8080, and the right token still works afterwards."""
    client = ctx.client("lambda-microvms")
    marker = ctx.unique_name("proto-")
    image = _provision_ready_image(ctx, marker)
    started = _run_microvm(ctx, image)
    microvm_id = started["microvmId"]
    running = _wait_for_microvm_state(ctx, microvm_id, {"RUNNING"})
    endpoint = running["endpoint"]

    good_token = client.create_microvm_auth_token(
        microvmIdentifier=microvm_id, expirationInMinutes=10, allowedPorts=[{"port": 8080}]
    )["authToken"]
    body = _http_get(ctx, endpoint, good_token)
    payload = json.loads(body)
    assert payload["status"] == "ok", f"expected status 'ok' from the guest app, got {payload!r}"
    assert payload["marker"] == marker, (
        f"expected the guest app's own marker {marker!r} back, got {payload.get('marker')!r} "
        "-- the response did not come from this run's guest process"
    )

    narrow_token = client.create_microvm_auth_token(
        microvmIdentifier=microvm_id, expirationInMinutes=10, allowedPorts=[{"port": 9999}]
    )["authToken"]
    status = _http_status(ctx, endpoint, narrow_token, port_header="8080")
    assert status == 403, f"expected 403 for a request to a port outside allowedPorts, got {status}"

    # Restore: the identical, correctly-scoped call still succeeds -- the 403 above is the
    # endpoint enforcing allowedPorts, not the proxy or the guest process having gone bad.
    body_after = _http_get(ctx, endpoint, good_token)
    payload_after = json.loads(body_after)
    assert payload_after["status"] == "ok" and payload_after["marker"] == marker, (
        f"the correctly-scoped token stopped working after the narrow-token probe: {payload_after!r}"
    )


def _auth_headers(token_parts: dict) -> dict:
    # authToken is a map of header name -> value, e.g. {"X-aws-proxy-auth": "..."}.
    return dict(token_parts)


def _http_get(ctx, endpoint: str, token_parts: dict) -> str:
    url = f"{ctx.endpoint_url(endpoint)}/"
    req = urllib.request.Request(url, headers=_auth_headers(token_parts))
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.read().decode("utf-8")


def _http_status(ctx, endpoint: str, token_parts: dict, port_header: str) -> int:
    url = f"{ctx.endpoint_url(endpoint)}/"
    headers = _auth_headers(token_parts)
    headers["X-aws-proxy-port"] = port_header
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code


def _app_zip_bytes(marker: str) -> bytes:
    app_js = (
        "const http = require('http');\n"
        "const server = http.createServer((req, res) => {\n"
        "  res.writeHead(200, { 'Content-Type': 'application/json' });\n"
        f"  res.end(JSON.stringify({{ status: 'ok', marker: '{marker}', path: req.url }}));\n"
        "});\n"
        "server.listen(8080, () => { console.log('listening'); });\n"
    )
    dockerfile = (
        "FROM node:24-alpine\n"
        "WORKDIR /app\n"
        "COPY app.js .\n"
        "EXPOSE 8080\n"
        'CMD ["node", "app.js"]\n'
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("app.js", app_js)
        zf.writestr("Dockerfile", dockerfile)
    return buf.getvalue()


def _create_code_artifact(ctx, marker: str) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-mvm-").lower().replace("_", "-")[:63]
    # S3 rejects an explicit LocationConstraint for us-east-1; every other region requires one.
    if ctx.region and ctx.region != "us-east-1":
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    else:
        s3.create_bucket(Bucket=bucket)
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-origin", "Value": "create"}]}
    )
    s3.put_object(Bucket=bucket, Key="app.zip", Body=_app_zip_bytes(marker))
    return f"s3://{bucket}/app.zip"


def _delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        for obj in s3.list_objects_v2(Bucket=bucket).get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_build_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-mvm-role-")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": ["sts:AssumeRole", "sts:TagSession"],
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": f"arn:aws:s3:::{bucket}/*"},
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "arn:aws:logs:*:*:*",
            },
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="mvm-build-policy", PolicyDocument=json.dumps(policy))
    return role_arn


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName="mvm-build-policy")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _pick_base_image_arn(ctx) -> str:
    client = ctx.client("lambda-microvms")
    items = client.list_managed_microvm_images().get("items", [])
    if not items:
        raise AssertionError("no Lambda-managed MicroVM base images are available in this account/region")
    return items[0]["imageArn"]


def _create_image_with_retry(client, *, name, base_arn, role_arn, code_uri, timeout_s=90.0, interval_s=3.0, **extra):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return client.create_microvm_image(
                name=name,
                baseImageArn=base_arn,
                buildRoleArn=role_arn,
                codeArtifact={"uri": code_uri},
                tags={"sim2real-origin": "create"},
                **extra,
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ResourceNotFoundException", "AccessDeniedException"):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _delete_image_when_ready(ctx, image_arn: str) -> None:
    client = ctx.client("lambda-microvms")
    try:
        _wait_for_image_state(
            ctx, image_arn, {"CREATED", "CREATE_FAILED", "UPDATED", "UPDATE_FAILED"}, timeout_s=900.0
        )
    except AssertionError:
        pass
    try:
        client.delete_microvm_image(imageIdentifier=image_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_for_image_state(ctx, image_arn, target_states, timeout_s=900.0, interval_s=5.0):
    client = ctx.client("lambda-microvms")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = client.get_microvm_image(imageIdentifier=image_arn)
        last = resp["state"]
        if last in target_states:
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"image {image_arn} never reached {target_states}, last state={last}")


def _wait_for_version_state(ctx, image_arn, version, target_states, timeout_s=900.0, interval_s=5.0):
    client = ctx.client("lambda-microvms")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = client.get_microvm_image_version(imageIdentifier=image_arn, imageVersion=version)
        last = resp["state"]
        if last in target_states:
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"version {version} of {image_arn} never reached {target_states}, last state={last}")


def _create_image(ctx, marker: str, **create_kwargs) -> dict:
    client = ctx.client("lambda-microvms")
    code_uri = _create_code_artifact(ctx, marker)
    bucket = code_uri.split("//", 1)[1].split("/", 1)[0]
    role_arn = _create_build_role(ctx, bucket)
    base_arn = _pick_base_image_arn(ctx)
    name = ctx.unique_name("sim2real-mvm-img-").replace("_", "-")[:64]
    resp = _create_image_with_retry(
        client, name=name, base_arn=base_arn, role_arn=role_arn, code_uri=code_uri, **create_kwargs
    )
    image_arn = resp["imageArn"]
    ctx.on_cleanup(lambda: _delete_image_when_ready(ctx, image_arn))
    return {
        "imageArn": image_arn,
        "imageVersion": resp["imageVersion"],
        "roleArn": role_arn,
        "codeUri": code_uri,
        "baseImageArn": base_arn,
        "name": name,
    }


def _provision_ready_image(ctx, marker: str) -> dict:
    image = _create_image(ctx, marker)
    img = _wait_for_image_state(ctx, image["imageArn"], {"CREATED", "CREATE_FAILED"})
    assert img["state"] == "CREATED", f"prerequisite image build failed: {img.get('stateReason')}"
    ver = _wait_for_version_state(ctx, image["imageArn"], image["imageVersion"], {"SUCCESSFUL", "FAILED"})
    assert ver["state"] == "SUCCESSFUL", f"prerequisite version build failed: {ver.get('stateReason')}"
    return image


def _network_connector_arn(ctx, name: str) -> str:
    return f"arn:aws:lambda:{ctx.region}:aws:network-connector:aws-network-connector:{name}"


def _terminate_microvm(ctx, microvm_id: str) -> None:
    client = ctx.client("lambda-microvms")
    try:
        client.terminate_microvm(microvmIdentifier=microvm_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_for_microvm_state(ctx, microvm_id, target_states, timeout_s=600.0, interval_s=5.0):
    client = ctx.client("lambda-microvms")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = client.get_microvm(microvmIdentifier=microvm_id)
        last = resp["state"]
        if last in target_states:
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"microvm {microvm_id} never reached {target_states}, last state={last}")


def _run_microvm(ctx, image: dict, **kwargs) -> dict:
    client = ctx.client("lambda-microvms")
    ingress = kwargs.pop("ingressNetworkConnectors", [_network_connector_arn(ctx, "ALL_INGRESS")])
    egress = kwargs.pop("egressNetworkConnectors", [_network_connector_arn(ctx, "INTERNET_EGRESS")])
    resp = client.run_microvm(
        imageIdentifier=image["imageArn"],
        ingressNetworkConnectors=ingress,
        egressNetworkConnectors=egress,
        **kwargs,
    )
    microvm_id = resp["microvmId"]
    ctx.on_cleanup(lambda: _terminate_microvm(ctx, microvm_id))
    return resp


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
