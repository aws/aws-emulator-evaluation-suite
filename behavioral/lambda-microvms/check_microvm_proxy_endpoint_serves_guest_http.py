"""microvm-proxy-endpoint-serves-guest-http."""
from __future__ import annotations

import io
import json
import re
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "microvm-proxy-endpoint-serves-guest-http"
GROUP = "microvm-proxy-data-plane"
SERVICES = ["lambda-microvms"]

_PAYLOAD = "sim2real-microvm-dataplane-ok"


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A GET with the X-aws-proxy-auth token to the microvm endpoint returns the guest's payload,
    and the same GET without the token is refused by the proxy with HTTP 403.
    """
    mvm = ctx.client("lambda-microvms")
    image_arn, _version = _build_a_guest_http_image(ctx, mvm)

    started = mvm.run_microvm(
        imageIdentifier=image_arn,
        maximumDurationInSeconds=600,
        ingressNetworkConnectors=[
            f"arn:aws:lambda:{ctx.region}:aws:network-connector:"
            f"aws-network-connector:HTTP_INGRESS"
        ],
    )
    microvm_id = started["microvmId"]
    ctx.on_cleanup(lambda: _terminate(mvm, microvm_id))
    endpoint = started["endpoint"]
    assert re.fullmatch(r"[A-Za-z0-9.-]+(:\d+)?", endpoint), (
        f"the proxy endpoint {endpoint!r} is not a well-formed host"
    )
    _await_microvm_state(mvm, microvm_id, {"RUNNING"}, 120)

    token = mvm.create_microvm_auth_token(
        microvmIdentifier=microvm_id,
        expirationInMinutes=15,
        allowedPorts=[{"allPorts": {}}],
    )["authToken"]
    assert sorted(token) == ["X-aws-proxy-auth"], (
        f"the auth token carries parts {sorted(token)!r}, expected ['X-aws-proxy-auth']"
    )

    # The proxy fronts the guest's port 8080 on 443; an explicit :8080 on the host times out.
    status, body = _get(
        f"{ctx.endpoint_url(endpoint)}/probe.txt", {"X-aws-proxy-auth": token["X-aws-proxy-auth"]}, 180
    )
    assert status == 200, f"the authenticated proxy GET answered HTTP {status}"
    assert body.strip() == _PAYLOAD, (
        f"the proxy returned {body[:200]!r}; the guest serves {_PAYLOAD!r}, so the request never "
        f"reached the process inside the microvm"
    )

    # The same request with no token is refused by the proxy, not by the guest.
    status, body = _get(f"{ctx.endpoint_url(endpoint)}/probe.txt", {}, 0)
    assert status == 403, (
        f"an unauthenticated proxy GET answered HTTP {status} with {body[:200]!r}, expected 403"
    )
    assert "Request missing authentication" in body, (
        f"the unauthenticated refusal body is {body[:200]!r}, expected it to name the missing "
        f"authentication"
    )




def _own_build_role(ctx, bucket: str) -> str:
    """A build role this check creates and deletes, allowed to read the code artifact in its
    own bucket and to write build logs."""
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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_own_role(iam, role_name))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:GetObjectVersion"], "Resource": f"arn:aws:s3:::{bucket}/*"},
            {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": f"arn:aws:s3:::{bucket}"},
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "arn:aws:logs:*:*:*",
            },
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="mvm-build-policy", PolicyDocument=json.dumps(policy))
    return role_arn


def _delete_own_role(iam, role_name: str) -> None:
    for call in (
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="mvm-build-policy"),
        lambda: iam.delete_role(RoleName=role_name),
    ):
        try:
            call()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise


def _create_image_retrying(mvm, budget: float = 90.0, **kwargs) -> dict:
    """CreateMicrovmImage, retried while a just-created build role is still propagating."""
    deadline = time.time() + budget
    while True:
        try:
            return mvm.create_microvm_image(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            propagating = err["Code"] == "AccessDeniedException" or "role" in err.get("Message", "").lower()
            if not propagating or time.time() >= deadline:
                raise
            time.sleep(5)


def _get(url: str, headers: dict, retry_budget: float) -> tuple[int, str]:
    """GET *url*, retrying only while the guest process may still be coming up."""
    deadline = time.time() + retry_budget
    while True:
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", "replace")
        except OSError as exc:
            if time.time() >= deadline:
                raise AssertionError(
                    f"the proxy endpoint {url!r} never answered: {exc!r}"
                ) from exc
            time.sleep(5)


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


def _await_image_state(mvm, image_arn: str, wanted: set[str], budget: float) -> dict:
    deadline = time.time() + budget
    seen = None
    while time.time() < deadline:
        seen = mvm.get_microvm_image(imageIdentifier=image_arn)
        if seen["state"] in wanted:
            return seen
        time.sleep(5)
    raise AssertionError(
        f"image {image_arn!r} never reached one of {sorted(wanted)!r} within {budget}s; "
        f"last state was {(seen or {}).get('state')!r}"
    )


def _await_microvm_state(mvm, microvm_id: str, wanted: set[str], budget: float) -> dict:
    deadline = time.time() + budget
    seen = None
    while time.time() < deadline:
        seen = mvm.get_microvm(microvmIdentifier=microvm_id)
        if seen["state"] in wanted:
            return seen
        time.sleep(2)
    raise AssertionError(
        f"microvm {microvm_id!r} never reached one of {sorted(wanted)!r} within {budget}s; "
        f"last state was {(seen or {}).get('state')!r}"
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


def _build_a_guest_http_image(ctx, mvm) -> tuple[str, str]:
    """Build an image whose guest serves _PAYLOAD over HTTP on port 8080.

    The ready hook stays DISABLED: enabling it makes the build probe the guest port and fail.
    """
    name = ctx.unique_name("sim2real-behav-mvmdp-")
    s3 = ctx.client("s3")

    s3.create_bucket(
        Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-origin", "Value": CHECK}]}
    )
    role = _own_build_role(ctx, name)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "Dockerfile",
            "FROM public.ecr.aws/amazonlinux/amazonlinux:2023\n"
            "RUN dnf install -y python3 && dnf clean all\n"
            "RUN mkdir -p /srv\n"
            f"RUN echo {_PAYLOAD} > /srv/probe.txt\n"
            f"RUN echo {_PAYLOAD} > /srv/index.html\n"
            'CMD ["/bin/sh","-c","cd /srv && python3 -m http.server 8080"]\n',
        )
    s3.put_object(Bucket=name, Key="code.zip", Body=buf.getvalue())

    created = _create_image_retrying(
        mvm,
        name=name,
        baseImageArn=_managed_base_image(mvm),
        buildRoleArn=role,
        codeArtifact={"uri": f"s3://{name}/code.zip"},
        tags={"sim2real-origin": CHECK},
    )
    image_arn = created["imageArn"]
    ctx.on_cleanup(lambda: _delete_image(mvm, image_arn))
    version = created["imageVersion"]

    settled = _await_image_state(mvm, image_arn, {"CREATED", "CREATE_FAILED"}, 300)
    ver = mvm.get_microvm_image_version(imageIdentifier=image_arn, imageVersion=version)
    assert settled["state"] == "CREATED" and ver["state"] == "SUCCESSFUL", (
        f"the guest image build did not succeed: image {settled['state']!r}, version "
        f"{ver['state']!r}, reason {ver.get('stateReason')!r}"
    )
    return image_arn, version


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
