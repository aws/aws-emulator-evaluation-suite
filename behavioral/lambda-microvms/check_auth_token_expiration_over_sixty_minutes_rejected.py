"""auth-token-expiration-over-sixty-minutes-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "auth-token-expiration-over-sixty-minutes-rejected"
GROUP = "microvm-auth-token"
SERVICES = ["lambda-microvms"]


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateMicrovmAuthToken refuses expirationInMinutes 61 and accepts 60, a cap the model omits.

    The microvm lookup runs before the range check, so 61 against an absent microvm is a 404.
    """
    mvm = ctx.client("lambda-microvms")
    image_arn, _version = _build_a_runnable_image(ctx, mvm)

    started = mvm.run_microvm(imageIdentifier=image_arn, maximumDurationInSeconds=600)
    microvm_id = started["microvmId"]
    ctx.on_cleanup(lambda: _terminate(mvm, microvm_id))
    _await_microvm_state(mvm, microvm_id, {"RUNNING"}, 120)

    code, message = _error(
        lambda: mvm.create_microvm_auth_token(
            microvmIdentifier=microvm_id,
            expirationInMinutes=61,
            allowedPorts=[{"allPorts": {}}],
        )
    )
    assert code == "ValidationException", (
        f"a 61-minute token answered {code!r}, expected ValidationException"
    )
    expected_message = "ExpirationMinutes 61 exceeded max allowed of 60."
    assert message == expected_message, (
        f"a 61-minute token answered message {message!r}, expected {expected_message!r}"
    )

    # The absent-microvm lookup wins over the range check, so the same value is a 404 there.
    absent_microvm = "microvm-00000000-0000-0000-0000-000000000000"
    code, message = _error(
        lambda: mvm.create_microvm_auth_token(
            microvmIdentifier=absent_microvm,
            expirationInMinutes=61,
            allowedPorts=[{"allPorts": {}}],
        )
    )
    assert code == "ResourceNotFoundException", (
        f"an over-large expiry against an absent microvm answered {code!r}; the microvm lookup "
        f"runs before the range check, so it must be ResourceNotFoundException"
    )
    expected_message = f"MicroVM not found: {absent_microvm}"
    assert message == expected_message, (
        f"an over-large expiry against an absent microvm answered message {message!r}, "
        f"expected {expected_message!r}"
    )

    # POSITIVE CONTROL: the boundary value itself is accepted and mints a proxy-auth header.
    minted = mvm.create_microvm_auth_token(
        microvmIdentifier=microvm_id,
        expirationInMinutes=60,
        allowedPorts=[{"allPorts": {}}],
    )
    assert sorted(minted["authToken"]) == ["X-aws-proxy-auth"], (
        f"the 60-minute token carries parts {sorted(minted['authToken'])!r}, expected exactly "
        f"['X-aws-proxy-auth']"
    )
    token = minted["authToken"]["X-aws-proxy-auth"]
    assert isinstance(token, str) and token.strip(), (
        f"the minted proxy-auth value must be a non-empty opaque string, got {token!r}"
    )


def _account(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _error(fn) -> tuple[str, str]:
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("the call unexpectedly SUCCEEDED where real AWS rejects it")


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


def _all_customer_images(mvm, **kw) -> list[dict]:
    out: list[dict] = []
    token = None
    while True:
        page = mvm.list_microvm_images(**kw, **({"nextToken": token} if token else {}))
        items = page["items"]
        out.extend(items)
        token = page.get("nextToken")
        if not token or not items:
            break
    return out


def _all_microvms(mvm, **kw) -> list[dict]:
    out: list[dict] = []
    token = None
    while True:
        page = mvm.list_microvms(**kw, **({"nextToken": token} if token else {}))
        items = page["items"]
        out.extend(items)
        token = page.get("nextToken")
        if not token or not items:
            break
    return out


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


def _build_a_runnable_image(ctx, mvm) -> tuple[str, str]:
    """Build a real, runnable MicroVM image and return (imageArn, imageVersion).

    RunMicrovm refuses a managed base image outright, so a customer image must be built first.
    """
    name = ctx.unique_name("sim2real-behav-mvm-")
    role = _create_build_role(ctx)
    s3 = ctx.client("s3")

    s3.create_bucket(
        Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    logs = ctx.client("logs")
    ctx.on_cleanup(lambda: _delete_log_group(logs, f"/aws/lambda-microvms/{name}"))
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-origin", "Value": "create"}]}
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "Dockerfile",
            "FROM public.ecr.aws/amazonlinux/amazonlinux:2023\n"
            "RUN echo sim2real > /sim2real.txt\n"
            'CMD ["/bin/sh","-c","while true; do sleep 30; done"]\n',
        )
    s3.put_object(Bucket=name, Key="code.zip", Body=buf.getvalue())

    created = _create_image_once_role_is_visible(mvm,
        name=name,
        baseImageArn=_managed_base_image(mvm),
        buildRoleArn=role,
        codeArtifact={"uri": f"s3://{name}/code.zip"},
        tags={"sim2real-origin": "create"},
    )
    image_arn = created["imageArn"]
    ctx.on_cleanup(lambda: _delete_image(mvm, image_arn))
    version = created["imageVersion"]

    settled = _await_image_state(mvm, image_arn, {"CREATED", "CREATE_FAILED"}, 260)
    ver = mvm.get_microvm_image_version(imageIdentifier=image_arn, imageVersion=version)
    assert settled["state"] == "CREATED" and ver["state"] == "SUCCESSFUL", (
        f"the image build did not succeed: image {settled['state']!r}, version "
        f"{ver['state']!r}, reason {ver.get('stateReason')!r}"
    )
    assert ver["status"] == "ACTIVE", (
        f"a successful build left the version {ver['status']!r}, expected ACTIVE"
    )
    return image_arn, version


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

    Lambda assumes the role to read the code artifact; the policy grants S3 reads and log writes.
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
