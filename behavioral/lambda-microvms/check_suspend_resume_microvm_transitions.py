"""suspend-resume-microvm-transitions."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "suspend-resume-microvm-transitions"
GROUP = "state-machine"
SERVICES = ["lambda-microvms"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """SuspendMicrovm reaches SUSPENDED and ResumeMicrovm returns to RUNNING with guest memory
    intact: the guest's per-boot id is unchanged and its request counter did not reset."""
    client = ctx.client("lambda-microvms")
    marker = ctx.unique_name("suspres-")
    image = _provision_ready_image(ctx, marker)
    started = _run_microvm(ctx, image)
    microvm_id = started["microvmId"]
    running = _wait_for_microvm_state(ctx, microvm_id, {"RUNNING"})
    endpoint = running["endpoint"]

    token = client.create_microvm_auth_token(
        microvmIdentifier=microvm_id, expirationInMinutes=15, allowedPorts=[{"port": 8080}]
    )["authToken"]

    first = _get_state(ctx, endpoint, token, retry_budget_s=90.0)
    assert first["marker"] == marker, f"guest served marker {first.get('marker')!r}, expected {marker!r}"
    boot_id = first["bootId"]
    second = _get_state(ctx, endpoint, token)
    assert second["bootId"] == boot_id, (
        f"bootId changed from {boot_id!r} to {second.get('bootId')!r} between two reads of the "
        f"same running microvm, before any suspend"
    )
    count_before_suspend = second["counter"]
    assert count_before_suspend > first["counter"], (
        f"the guest's in-memory request counter did not advance between two live reads "
        f"({first['counter']} then {count_before_suspend}); it is not tracking real requests"
    )

    client.suspend_microvm(microvmIdentifier=microvm_id)
    suspended = _wait_for_microvm_state(ctx, microvm_id, {"SUSPENDED", "TERMINATED"})
    assert suspended["state"] == "SUSPENDED", f"microvm did not reach SUSPENDED: {suspended.get('state')}"

    client.resume_microvm(microvmIdentifier=microvm_id)
    running_again = _wait_for_microvm_state(ctx, microvm_id, {"RUNNING", "TERMINATED"})
    assert running_again["state"] == "RUNNING", f"microvm did not resume to RUNNING: {running_again.get('state')}"

    resumed_token = client.create_microvm_auth_token(
        microvmIdentifier=microvm_id, expirationInMinutes=15, allowedPorts=[{"port": 8080}]
    )["authToken"]
    after = _get_state(ctx, running_again["endpoint"], resumed_token, retry_budget_s=90.0)
    assert after["bootId"] == boot_id, (
        f"guest process bootId changed from {boot_id!r} to {after.get('bootId')!r} across "
        f"suspend/resume -- ResumeMicrovm booted a fresh guest instead of restoring the "
        f"suspended one"
    )
    assert after["counter"] >= count_before_suspend, (
        f"the guest's in-memory request counter was {count_before_suspend} immediately before "
        f"suspend and reads {after.get('counter')} after resume -- ResumeMicrovm did not "
        f"restore the process's memory state"
    )


def _app_zip_bytes(marker: str) -> bytes:
    app_js = (
        "const http = require('http');\n"
        "const bootId = Math.random().toString(36).slice(2);\n"
        "let counter = 0;\n"
        "const server = http.createServer((req, res) => {\n"
        "  counter += 1;\n"
        "  res.writeHead(200, { 'Content-Type': 'application/json' });\n"
        f"  res.end(JSON.stringify({{ status: 'ok', marker: '{marker}', bootId, counter, path: req.url }}));\n"
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


def _get_state(ctx, endpoint: str, token_parts: dict, retry_budget_s: float = 30.0) -> dict:
    """GET the guest's JSON status through the proxy, retrying only while it may still be
    coming up (right after RUNNING, or right after a resume)."""
    url = f"{ctx.endpoint_url(endpoint)}/"
    deadline = time.monotonic() + retry_budget_s
    while True:
        req = urllib.request.Request(url, headers=dict(token_parts))
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code >= 500 and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise AssertionError(
                f"the microvm endpoint {url!r} answered HTTP {exc.code}: "
                f"{exc.read().decode('utf-8', 'replace')[:200]!r}"
            ) from exc
        except OSError as exc:
            if time.monotonic() >= deadline:
                raise AssertionError(f"the microvm endpoint {url!r} never answered: {exc!r}") from exc
            time.sleep(5)


def _create_code_artifact(ctx, marker: str) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-mvm-").lower().replace("_", "-")[:63]
    if ctx.region and ctx.region != "us-east-1":
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    else:
        s3.create_bucket(Bucket=bucket)
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
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
        client,
        name=name,
        base_arn=base_arn,
        role_arn=role_arn,
        code_uri=code_uri,
        tags={"sim2real": CHECK},
        **create_kwargs,
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
