"""suspend-resume-preserves-guest-memory-and-process-identity."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "suspend-resume-preserves-guest-memory-and-process-identity"
GROUP = "microvm-state-machine"
SERVICES = ["lambda-microvms"]

#: The image build provisions a real snapshot build; this is generous headroom.
_IMAGE_BUILD_BUDGET_S = 420.0
#: Each control-plane transition (typically a few seconds).
_MICROVM_STATE_BUDGET_S = 180.0
#: The guest process coming up behind the proxy, and coming back after a restore.
_GUEST_READY_BUDGET_S = 180.0
#: How long the proxy gets to answer while the microvm is SUSPENDED before "no answer" is
#: itself the observation. Only the negative leg uses this.
_SUSPENDED_PROBE_TIMEOUT_S = 30.0
#: A platform cap on the microvm's whole life, so an interrupted teardown cannot leak a running
#: microvm for longer. Above this check's ~1290s worst case.
_MICROVM_MAX_DURATION = 1800

_AUTH_HEADER = "X-aws-proxy-auth"
_GUEST_PORT = 8080

_GUEST_APP = '''\
import http.server
import json
import os
import urllib.parse

_MEM = {}
_DISK = "/var/tmp/sim2real-marker"


def _read(path):
    with open(path) as fh:
        return fh.read()


def _ident():
    # starttime is field 22 of /proc/self/stat (1-indexed); the fields after the comm
    # field's closing paren begin at field 3, so it is index 19 there.
    stat_tail = _read("/proc/self/stat").rsplit(")", 1)[1].split()
    return {
        "boot_id": _read("/proc/sys/kernel/random/boot_id").strip(),
        "pid": os.getpid(),
        "starttime": stat_tail[19],
    }


_IDENT = _ident()


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        if parsed.path == "/id":
            body = _IDENT
        elif parsed.path == "/set":
            value = query["v"][0]
            _MEM["v"] = value
            with open(_DISK, "w") as fh:
                fh.write(value)
            body = {"stored": value}
        elif parsed.path == "/get":
            disk = _read(_DISK) if os.path.exists(_DISK) else None
            body = {"mem": _MEM.get("v"), "disk": disk}
        else:
            body = {"error": "no such path: " + parsed.path}
        raw = json.dumps(body).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args):
        pass


http.server.HTTPServer(("0.0.0.0", %(port)d), Handler).serve_forever()
''' % {"port": _GUEST_PORT}


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """After suspend and resume the guest reports the same boot_id, pid and start time and keeps its
    in-memory and on-disk values, read over the proxy endpoint; while suspended it serves no 200.
    """
    mvm = ctx.client("lambda-microvms")
    image_arn, version = _build_a_guest_state_image(ctx, mvm)

    # No idlePolicy: auto-suspend and auto-resume would both interfere with the subject, so
    # the only transitions in this run are the two this check makes.
    started = mvm.run_microvm(
        imageIdentifier=image_arn,
        maximumDurationInSeconds=_MICROVM_MAX_DURATION,
        ingressNetworkConnectors=[_network_connector(ctx, "HTTP_INGRESS")],
    )
    microvm_id = started["microvmId"]
    ctx.on_cleanup(lambda: _terminate(mvm, microvm_id))
    endpoint = started["endpoint"]
    assert started["imageVersion"] == version, (
        f"the microvm is backed by image version {started['imageVersion']!r}, expected the "
        f"version this check built, {version!r}"
    )

    _await_microvm_state(mvm, microvm_id, {"RUNNING"})
    headers = {_AUTH_HEADER: _auth_token(mvm, microvm_id)}

    ident_before = _get_json(f"{ctx.endpoint_url(endpoint)}/id", headers, _GUEST_READY_BUDGET_S)
    for field in ("boot_id", "pid", "starttime"):
        assert ident_before[field], (
            f"the guest reported no {field} before the suspend ({ident_before!r}); the "
            f"identity triple is what distinguishes a restore from a reboot, so the rest of "
            f"this check cannot mean anything without it"
        )

    nonce = ctx.unique_name("sim2real-guest-state-")
    stored = _get_json(f"{ctx.endpoint_url(endpoint)}/set?v={nonce}", headers, _GUEST_READY_BUDGET_S)
    assert stored["stored"] == nonce, (
        f"the guest echoed {stored['stored']!r} for the value it was asked to store, "
        f"expected {nonce!r}"
    )
    before = _get_json(f"{ctx.endpoint_url(endpoint)}/get", headers, _GUEST_READY_BUDGET_S)
    assert before["mem"] == nonce and before["disk"] == nonce, (
        f"before any suspend the guest reports mem={before['mem']!r} disk={before['disk']!r}, "
        f"expected both to be {nonce!r}; the pre-suspend baseline must hold or the "
        f"post-resume comparison proves nothing"
    )

    mvm.suspend_microvm(microvmIdentifier=microvm_id)
    _await_microvm_state(mvm, microvm_id, {"SUSPENDED"})

    # With no auto-resume policy a suspended guest is frozen and cannot answer a request.
    suspended_status, suspended_body = _probe_status(
        f"{ctx.endpoint_url(endpoint)}/get", headers, _SUSPENDED_PROBE_TIMEOUT_S
    )
    assert suspended_status != 200, (
        f"while the microvm was SUSPENDED the proxy still served the guest: HTTP "
        f"{suspended_status} {suspended_body[:120]!r}; a suspended guest is frozen and "
        f"cannot answer, so the suspend did not take effect"
    )

    mvm.resume_microvm(microvmIdentifier=microvm_id)
    _await_microvm_state(mvm, microvm_id, {"RUNNING"})
    # A fresh auth token after the resume, in case a pre-suspend token does not survive it.
    headers = {_AUTH_HEADER: _auth_token(mvm, microvm_id)}

    ident_after = _get_json(f"{ctx.endpoint_url(endpoint)}/id", headers, _GUEST_READY_BUDGET_S)
    assert ident_after == ident_before, (
        f"after the resume the guest identifies as {ident_after!r}, before the suspend it "
        f"was {ident_before!r}; a changed boot_id, pid or start time means the guest was "
        f"REBOOTED, not restored from a snapshot"
    )

    after = _get_json(f"{ctx.endpoint_url(endpoint)}/get", headers, _GUEST_READY_BUDGET_S)
    assert after["disk"] == nonce, (
        f"after the resume the guest reads {after['disk']!r} off disk, expected {nonce!r}; "
        f"ResumeMicrovm is documented to restore the disk state"
    )
    assert after["mem"] == nonce, (
        f"after the resume the guest's in-process memory holds {after['mem']!r}, expected "
        f"{nonce!r}; SuspendMicrovm is documented to preserve the full memory state, so a "
        f"value that survives on disk but not in memory means the guest was restarted"
    )


def _account(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _network_connector(ctx, name: str) -> str:
    return (
        f"arn:aws:lambda:{ctx.region}:aws:network-connector:aws-network-connector:{name}"
    )


def _auth_token(mvm, microvm_id: str) -> str:
    token = mvm.create_microvm_auth_token(
        microvmIdentifier=microvm_id,
        expirationInMinutes=30,
        allowedPorts=[{"allPorts": {}}],
    )["authToken"]
    assert _AUTH_HEADER in token, (
        f"CreateMicrovmAuthToken returned parts {sorted(token)!r}, expected one named "
        f"{_AUTH_HEADER!r}"
    )
    return token[_AUTH_HEADER]


def _get_json(url: str, headers: dict, budget_s: float) -> dict:
    """GET *url* and decode a JSON body, raising if it never answers 200 within *budget_s*.

    The retry covers only the guest process coming up behind the proxy.
    """
    deadline = time.time() + budget_s
    while True:
        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                status, raw = response.status, response.read()
                break
        except urllib.error.HTTPError as exc:
            status, raw = exc.code, exc.read()
            break
        except OSError as exc:
            if time.time() >= deadline:
                raise AssertionError(
                    f"the proxy endpoint {url!r} never answered within {budget_s}s: {exc!r}"
                ) from exc
            time.sleep(5)
    body = raw.decode("utf-8", "replace")
    assert status == 200, f"GET {url!r} answered HTTP {status} with {body[:200]!r}"
    return json.loads(body)


def _probe_status(url: str, headers: dict, timeout_s: float) -> tuple[int | None, str]:
    """One GET, reporting the status and body; a None status means no HTTP answer in *timeout_s*."""
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout_s) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except OSError as exc:
        return None, f"no HTTP answer within {timeout_s}s: {exc!r}"


def _managed_base_image(mvm) -> str:
    arns: list[str] = []
    token = None
    while True:
        page = mvm.list_managed_microvm_images(**({"nextToken": token} if token else {}))
        items = page["items"]
        arns.extend(i["imageArn"] for i in items)
        token = page.get("nextToken")
        if not token or not items:
            break
    assert arns, "ListManagedMicrovmImages returned no managed base image to build from"
    return sorted(arns)[0]


def _await_image_state(mvm, image_arn: str, wanted: set[str]) -> dict:
    deadline = time.time() + _IMAGE_BUILD_BUDGET_S
    seen = None
    while time.time() < deadline:
        seen = mvm.get_microvm_image(imageIdentifier=image_arn)
        if seen["state"] in wanted:
            return seen
        time.sleep(5)
    raise AssertionError(
        f"image {image_arn!r} never reached one of {sorted(wanted)!r} within "
        f"{_IMAGE_BUILD_BUDGET_S}s; last state was {(seen or {}).get('state')!r}"
    )


def _await_microvm_state(mvm, microvm_id: str, wanted: set[str]) -> dict:
    """Poll GetMicrovm until the state is in *wanted*, raising on timeout."""
    deadline = time.time() + _MICROVM_STATE_BUDGET_S
    seen = None
    while time.time() < deadline:
        seen = mvm.get_microvm(microvmIdentifier=microvm_id)
        if seen["state"] in wanted:
            return seen
        time.sleep(2)
    raise AssertionError(
        f"microvm {microvm_id!r} never reached one of {sorted(wanted)!r} within "
        f"{_MICROVM_STATE_BUDGET_S}s; last state was {(seen or {}).get('state')!r}"
    )


def _delete_image(mvm, image_arn: str) -> None:
    deadline = time.time() + 150
    while True:
        try:
            mvm.delete_microvm_image(imageIdentifier=image_arn)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            if time.time() >= deadline:
                raise
            time.sleep(5)


def _terminate(mvm, microvm_id: str) -> None:
    try:
        mvm.terminate_microvm(microvmIdentifier=microvm_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    token = None
    while True:
        page = s3.list_objects_v2(
            Bucket=bucket, **({"ContinuationToken": token} if token else {})
        )
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        token = page.get("NextContinuationToken")
        if not token:
            break
    s3.delete_bucket(Bucket=bucket)


def _build_a_guest_state_image(ctx, mvm) -> tuple[str, str]:
    """Build an image whose guest serves /id, /set and /get over HTTP on the guest port.

    microvmImageHooks.ready is left disabled: enabling it makes the build probe the guest port
    and fail the image.
    """
    name = ctx.unique_name("sim2real-behav-mvmstate-")
    role = _create_build_role(ctx)
    s3 = ctx.client("s3")

    s3.create_bucket(
        Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    logs = ctx.client("logs")
    ctx.on_cleanup(lambda: _delete_log_group(logs, f"/aws/lambda-microvms/{name}"))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("app.py", _GUEST_APP)
        zf.writestr(
            "Dockerfile",
            "FROM public.ecr.aws/amazonlinux/amazonlinux:2023\n"
            "RUN dnf install -y python3 && dnf clean all\n"
            "RUN mkdir -p /srv\n"
            "COPY app.py /srv/app.py\n"
            'CMD ["python3","/srv/app.py"]\n',
        )
    s3.put_object(Bucket=name, Key="code.zip", Body=buf.getvalue())

    created = _create_image_once_role_is_visible(mvm,
        name=name,
        baseImageArn=_managed_base_image(mvm),
        buildRoleArn=role,
        codeArtifact={"uri": f"s3://{name}/code.zip"},
    )
    image_arn = created["imageArn"]
    ctx.on_cleanup(lambda: _delete_image(mvm, image_arn))
    version = created["imageVersion"]

    settled = _await_image_state(mvm, image_arn, {"CREATED", "CREATE_FAILED"})
    ver = mvm.get_microvm_image_version(imageIdentifier=image_arn, imageVersion=version)
    assert settled["state"] == "CREATED" and ver["state"] == "SUCCESSFUL", (
        f"the guest image build did not succeed: image {settled['state']!r}, version "
        f"{ver['state']!r}, reason {ver.get('stateReason')!r}"
    )
    return image_arn, version


def _delete_log_group(logs, group: str) -> None:
    """Delete the log group the platform writes the image's microvm logs to, if it exists."""
    try:
        logs.delete_log_group(logGroupName=group)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


_BUILD_ROLE_POLICY = "sim2real-mvm-build"


def _create_build_role(ctx) -> str:
    """Create the image build role this check owns and return its ARN.

    Lambda assumes the role to read the code artifact, so the inline policy grants the S3
    reads on the check's own sim2real- buckets and the build's log writes.
    """
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-mvm-role-")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession"],
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_build_role(iam, role_name))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket"],
                "Resource": ["arn:aws:s3:::sim2real-*", "arn:aws:s3:::sim2real-*/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "arn:aws:logs:*:*:*",
            },
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName=_BUILD_ROLE_POLICY, PolicyDocument=json.dumps(policy)
    )
    return role_arn


def _delete_build_role(iam, role_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=_BUILD_ROLE_POLICY)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_image_once_role_is_visible(mvm, budget: float = 90.0, **kwargs) -> dict:
    """CreateMicrovmImage, retried while the freshly created build role propagates."""
    deadline = time.time() + budget
    while True:
        try:
            return mvm.create_microvm_image(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("AccessDeniedException", "ResourceNotFoundException", "ValidationException"):
                raise
            if "role" not in exc.response["Error"].get("Message", "").lower():
                raise
            if time.time() >= deadline:
                raise
            time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
