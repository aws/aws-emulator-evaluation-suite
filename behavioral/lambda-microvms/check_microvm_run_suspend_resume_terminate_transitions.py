"""microvm-run-suspend-resume-terminate-transitions."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "microvm-run-suspend-resume-terminate-transitions"
GROUP = "microvm-state-machine"
SERVICES = ["lambda-microvms"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A microvm walks PENDING -> RUNNING -> SUSPENDED -> RUNNING -> TERMINATED as read back by
    GetMicrovm/ListMicrovms, keeping its identity fields and startedAt, and gaining terminatedAt.
    """
    mvm = ctx.client("lambda-microvms")
    image_arn, version = _build_a_runnable_image(ctx, mvm)

    started = mvm.run_microvm(imageIdentifier=image_arn, maximumDurationInSeconds=600)
    microvm_id = started["microvmId"]
    ctx.on_cleanup(lambda: _terminate(mvm, microvm_id))
    endpoint = started["endpoint"]
    assert started["state"] == "PENDING", (
        f"RunMicrovm returned state {started['state']!r}, expected PENDING"
    )
    assert started["imageVersion"] == version, (
        f"the microvm is backed by version {started['imageVersion']!r}, expected {version!r}"
    )
    assert "terminatedAt" not in started, (
        f"a freshly started microvm already reports terminatedAt "
        f"{started.get('terminatedAt')!r}"
    )

    running = _await_microvm_state(mvm, microvm_id, {"RUNNING"}, 120)
    assert running["endpoint"] == endpoint, (
        f"the endpoint changed from {endpoint!r} to {running['endpoint']!r} on reaching RUNNING"
    )
    listed = [m for m in _all_microvms(mvm, imageIdentifier=image_arn)
              if m["microvmId"] == microvm_id]
    assert [m["state"] for m in listed] == ["RUNNING"], (
        f"ListMicrovms scoped to the image reports {[m['state'] for m in listed]!r} for "
        f"{microvm_id!r} while GetMicrovm says RUNNING"
    )

    mvm.suspend_microvm(microvmIdentifier=microvm_id)
    suspended = _await_microvm_state(mvm, microvm_id, {"SUSPENDED"}, 120)
    assert suspended["endpoint"] == endpoint, (
        f"suspending moved the endpoint from {endpoint!r} to {suspended['endpoint']!r}"
    )
    assert "terminatedAt" not in suspended, (
        f"a SUSPENDED microvm reports terminatedAt {suspended.get('terminatedAt')!r}"
    )

    mvm.resume_microvm(microvmIdentifier=microvm_id)
    resumed = _await_microvm_state(mvm, microvm_id, {"RUNNING"}, 120)
    assert (resumed["microvmId"], resumed["endpoint"], resumed["imageArn"]) == (
        microvm_id, endpoint, image_arn
    ), (
        f"resume returned a different microvm: "
        f"{(resumed['microvmId'], resumed['endpoint'], resumed['imageArn'])!r}"
    )
    assert resumed["startedAt"] == running["startedAt"], (
        f"startedAt moved from {running['startedAt']!r} to {resumed['startedAt']!r} across a "
        f"suspend/resume cycle; it records the original start"
    )

    mvm.terminate_microvm(microvmIdentifier=microvm_id)
    terminated = _await_microvm_state(mvm, microvm_id, {"TERMINATED"}, 120)
    assert "terminatedAt" in terminated, (
        f"a TERMINATED microvm reports no terminatedAt: {sorted(terminated)!r}"
    )
    assert terminated["terminatedAt"] > terminated["startedAt"], (
        f"terminatedAt {terminated['terminatedAt']!r} is not after startedAt "
        f"{terminated['startedAt']!r}"
    )
    still_listed = [m for m in _all_microvms(mvm, imageIdentifier=image_arn)
                    if m["microvmId"] == microvm_id]
    assert [m["state"] for m in still_listed] == ["TERMINATED"], (
        f"after termination ListMicrovms reports {[m['state'] for m in still_listed]!r} for "
        f"{microvm_id!r}; real AWS keeps the terminated record listed"
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


def _error_code(fn) -> str:
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
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
    s3 = ctx.client("s3")

    s3.create_bucket(
        Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    role = _own_build_role(ctx, name)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "Dockerfile",
            "FROM public.ecr.aws/amazonlinux/amazonlinux:2023\n"
            "RUN echo sim2real > /sim2real.txt\n"
            'CMD ["/bin/sh","-c","while true; do sleep 30; done"]\n',
        )
    s3.put_object(Bucket=name, Key="code.zip", Body=buf.getvalue())

    created = _create_image_retrying(
        mvm,
        name=name,
        baseImageArn=_managed_base_image(mvm),
        buildRoleArn=role,
        codeArtifact={"uri": f"s3://{name}/code.zip"},
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
