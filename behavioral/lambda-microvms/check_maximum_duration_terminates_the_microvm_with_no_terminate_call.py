"""maximum-duration-terminates-the-microvm-with-no-terminate-call."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "maximum-duration-terminates-the-microvm-with-no-terminate-call"
GROUP = "microvm-state-machine"
SERVICES = ["lambda-microvms"]

#: The lifetime this check asks the platform to enforce. Inside the model's fixed 1..28800
#: range, and chosen to sit clearly above the PENDING->RUNNING dwell (seconds).
_MAX_DURATION = 20
#: Slack on the LOWER bound, absorbing clock skew between the caller and the service.
_CLOCK_TOLERANCE_S = 10.0
#: Slack on the UPPER bound: how late the platform may be and still count as enforcing.
_OVERRUN_ALLOWANCE_S = 180.0

#: The image build provisions a real Firecracker snapshot build.
_IMAGE_BUILD_BUDGET_S = 420.0
#: Reaching RUNNING; each transition is typically observed within a few seconds.
_RUNNING_BUDGET_S = 180.0
#: Waiting for the PLATFORM to terminate. Must exceed _MAX_DURATION + _OVERRUN_ALLOWANCE_S,
#: or the poll would expire before the deadline it is testing.
_TERMINATION_BUDGET_S = 600.0


# timing:real-time — ttl: 20 s
@tags("axis:happy-path", "cap:c4", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """maximumDurationInSeconds is enforced: with no TerminateMicrovm call the microvm reaches
    TERMINATED on its own, no earlier than its deadline and not much later, with a stateReason.
    """
    mvm = ctx.client("lambda-microvms")
    image_arn, version = _build_a_runnable_image(ctx, mvm)

    # The local clock is started BEFORE the microvm exists, so startedAt cannot be earlier
    # than this instant and the local lower bound below is conservative in the safe
    # direction. No ingress connector: nothing talks to this guest.
    launched_at = time.monotonic()
    started = mvm.run_microvm(
        imageIdentifier=image_arn, maximumDurationInSeconds=_MAX_DURATION
    )
    microvm_id = started["microvmId"]
    ctx.on_cleanup(lambda: _terminate(mvm, microvm_id))

    # Preconditions, not the verdict: the echo only establishes that the request this check
    # believes it made is the request the target accepted.
    assert started["maximumDurationInSeconds"] == _MAX_DURATION, (
        f"RunMicrovm echoed maximumDurationInSeconds "
        f"{started['maximumDurationInSeconds']!r}, expected {_MAX_DURATION!r}; the rest of "
        f"this check tests the deadline it thinks it asked for"
    )
    assert started["imageVersion"] == version, (
        f"the microvm is backed by image version {started['imageVersion']!r}, expected the "
        f"version this check built, {version!r}"
    )

    running = _await_microvm_state(mvm, microvm_id, {"RUNNING"}, _budget_s(ctx, _RUNNING_BUDGET_S), ctx=ctx)
    started_at = running["startedAt"]

    # THE SUBJECT. No TerminateMicrovm call is made anywhere between here and the assertions
    # below; the only thing that can move this microvm is the platform enforcing its deadline.
    terminated = _await_microvm_state(
        mvm, microvm_id, {"TERMINATED"}, _budget_s(ctx, _TERMINATION_BUDGET_S), ctx=ctx
    )
    observed_s = time.monotonic() - launched_at

    # Lower bound 1 -- on the LOCAL clock, so real time must actually have passed. A target
    # that terminates instantly and back-dates terminatedAt fails here and nowhere else.
    assert observed_s >= _MAX_DURATION - _CLOCK_TOLERANCE_S, (
        f"the microvm was observed TERMINATED {observed_s:.1f}s after RunMicrovm was called, "
        f"but its maximumDurationInSeconds was {_MAX_DURATION}; the platform must not end it "
        f"before its deadline (tolerance {_CLOCK_TOLERANCE_S}s)"
    )

    assert "terminatedAt" in terminated, (
        f"a platform-terminated microvm reports no terminatedAt; the fields present are "
        f"{sorted(terminated)!r}"
    )
    assert terminated["startedAt"] == started_at, (
        f"startedAt moved from {started_at!r} to {terminated['startedAt']!r} when the "
        f"platform terminated the microvm; the death certificate must not rewrite the birth "
        f"certificate"
    )
    lifetime_s = (terminated["terminatedAt"] - started_at).total_seconds()

    # Lower bound 2 -- on the target's OWN reported timestamps, so a target that waits the
    # right amount of real time but misreports the interval fails.
    assert lifetime_s >= _MAX_DURATION - _CLOCK_TOLERANCE_S, (
        f"the microvm reports it lived {lifetime_s:.1f}s (startedAt {started_at!r} -> "
        f"terminatedAt {terminated['terminatedAt']!r}) against a maximumDurationInSeconds of "
        f"{_MAX_DURATION}; it must not be ended before its deadline"
    )
    # Upper bound -- the deadline is a deadline, not a suggestion.
    assert lifetime_s <= _MAX_DURATION + _OVERRUN_ALLOWANCE_S, (
        f"the microvm reports it lived {lifetime_s:.1f}s against a maximumDurationInSeconds "
        f"of {_MAX_DURATION}, overrunning by more than the {_OVERRUN_ALLOWANCE_S}s allowed; "
        f"a stored-but-unenforced duration looks exactly like this"
    )

    reason = terminated.get("stateReason")
    assert reason, (
        f"a microvm terminated by its own maximumDurationInSeconds reports stateReason "
        f"{reason!r}; the platform ended it for a reason it must be able to state"
    )

    # Independent read, different operation: ListMicrovms must agree, and must still carry
    # the record. The mutation here was the platform's, so both reads are independent of it.
    listed = [
        m for m in _all_microvms(mvm, imageIdentifier=image_arn)
        if m["microvmId"] == microvm_id
    ]
    assert [m["state"] for m in listed] == ["TERMINATED"], (
        f"ListMicrovms scoped to the image reports {[m['state'] for m in listed]!r} for "
        f"{microvm_id!r} while GetMicrovm says TERMINATED"
    )

    # Freeze detector: reading a dead microvm must not advance it. Three consecutive reads
    # must return the identical state, terminatedAt and startedAt.
    frozen = [
        (r["state"], r["startedAt"], r["terminatedAt"])
        for r in (mvm.get_microvm(microvmIdentifier=microvm_id) for _ in range(3))
    ]
    expected = ("TERMINATED", started_at, terminated["terminatedAt"])
    assert frozen == [expected] * 3, (
        f"three consecutive GetMicrovm reads of the platform-terminated microvm returned "
        f"{frozen!r}, expected {expected!r} every time; reads must not advance state or "
        f"rewrite the termination record"
    )




def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _account(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


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


def _await_image_state(mvm, image_arn: str, wanted: set[str], budget_s: float, ctx=None) -> dict:
    """Poll GetMicrovmImage until the build settles, raising on timeout.

    CREATE_FAILED stops the poll early; the caller then asserts CREATED, so failure never passes.
    """
    deadline = time.monotonic() + budget_s
    seen = None
    while True:
        seen = mvm.get_microvm_image(imageIdentifier=image_arn)
        if seen["state"] in wanted:
            return seen
        if time.monotonic() >= deadline:
            break
        time.sleep(1)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"image {image_arn!r} to reach one of {sorted(wanted)!r}: the run budget ended first; not graded")
    raise AssertionError(
        f"image {image_arn!r} never reached one of {sorted(wanted)!r} within "
        f"{budget_s:.0f}s; last state was {(seen or {}).get('state')!r}"
    )


def _await_microvm_state(mvm, microvm_id: str, wanted: set[str], budget_s: float, ctx=None) -> dict:
    """Poll GetMicrovm until the state is in *wanted*, raising on timeout."""
    deadline = time.monotonic() + budget_s
    seen = None
    while True:
        seen = mvm.get_microvm(microvmIdentifier=microvm_id)
        if seen["state"] in wanted:
            return seen
        if time.monotonic() >= deadline:
            break
        time.sleep(1)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"microvm {microvm_id!r} to reach one of {sorted(wanted)!r}: the run budget ended first; not graded")
    raise AssertionError(
        f"microvm {microvm_id!r} never reached one of {sorted(wanted)!r} within {budget_s:.0f}s; "
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
            time.sleep(2)


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


def _build_a_runnable_image(ctx, mvm) -> tuple[str, str]:
    """Build a real, runnable MicroVM image and return (imageArn, imageVersion).

    RunMicrovm refuses a managed base image outright, so a customer image must be built first.
    """
    name = ctx.unique_name("sim2real-behav-mvmdur-")
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
    )
    image_arn = created["imageArn"]
    ctx.on_cleanup(lambda: _delete_image(mvm, image_arn))
    version = created["imageVersion"]

    settled = _await_image_state(
        mvm, image_arn, {"CREATED", "CREATE_FAILED"}, _budget_s(ctx, _IMAGE_BUILD_BUDGET_S), ctx=ctx
    )
    ver = mvm.get_microvm_image_version(imageIdentifier=image_arn, imageVersion=version)
    assert settled["state"] == "CREATED" and ver["state"] == "SUCCESSFUL", (
        f"the image build did not succeed: image {settled['state']!r}, version "
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
            time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
