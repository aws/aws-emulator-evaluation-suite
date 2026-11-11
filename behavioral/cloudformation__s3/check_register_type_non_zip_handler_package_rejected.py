"""register-type-non-zip-handler-package-rejected."""
# There is no valid-package positive control: registering a real resource type takes minutes.
# Instead the async pipeline must run (token, terminal state) and end FAILED with a stated cause.
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-type-non-zip-handler-package-rejected"
GROUP = "negative-classes"
SERVICES = ["cloudformation", "s3"]

NOT_A_ZIP = b"dummy\n"
ARTIFACT_NOT_ZIP = "not a valid ZIP file"
REGISTRATION_TIMEOUT_S = 300.0


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A handler package that is not a zip fails type registration and leaves no registered type.
    RegisterType is asynchronous, so the verdict comes from a DescribeTypeRegistration poll.
    """
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")

    # --- Setup: a six-byte non-zip in S3 ----------------------------------------------------------
    bucket = ctx.unique_name("sim2real-xsvc-typepkg-")
    s3.create_bucket(
        Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
    ) if ctx.region != "us-east-1" else s3.create_bucket(Bucket=bucket)
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    key = "not-a-zip.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=NOT_A_ZIP)

    type_name = f"Sim2Real::Behav::Probe{ctx.unique_name('').replace('-', '')[:8]}"

    # --- Beat 1: RegisterType is asynchronous and must issue a token -------------------------------
    # Asserted so a target that refuses the call outright is distinguishable from one that accepts the
    # bad package: the former raises here, the latter proceeds to Beat 2 and fails it.
    token = cfn.register_type(
        Type="RESOURCE",
        TypeName=type_name,
        SchemaHandlerPackage=f"s3://{bucket}/{key}",
    )["RegistrationToken"]
    assert token, f"RegisterType must return a RegistrationToken; got {token!r}"

    # --- Beat 2: the registration must reach FAILED, with a stated reason -------------------------
    registration = _await_terminal(cfn, token)
    status = registration["ProgressStatus"]
    assert status == "FAILED", (
        f"a non-zip handler package cannot register; expected ProgressStatus FAILED, got {status!r} "
        f"({registration!r}). COMPLETE here means the package was never opened"
    )
    # The Description naming the cause shows the artifact was opened, not merely accepted.
    # AWS mints TypeArn and TypeVersionArn even on FAILED, so only ProgressStatus is asserted.
    # message varies: the Description embeds a per-registration error id in brackets.
    assert ARTIFACT_NOT_ZIP in (registration.get("Description") or ""), (
        f"the failure must name the cause ({ARTIFACT_NOT_ZIP!r}) -- that is what shows the package was "
        f"opened and validated; got Description={registration.get('Description')!r}"
    )

    # --- Beat 3: effect-absent -- the type never became describable --------------------------------
    error = _client_error(lambda: cfn.describe_type(Type="RESOURCE", TypeName=type_name))
    assert error.get("Code") == "TypeNotFoundException", (
        f"a failed registration must leave no registered type {type_name!r}; describe_type gave "
        f"{error.get('Code')!r}: {error.get('Message')!r}"
    )
    expected = f"The type '{type_name}' cannot be found."
    assert error.get("Message") == expected, (
        f"describe_type message {error.get('Message')!r} != {expected!r}"
    )


def _await_terminal(cfn, token: str) -> dict:
    """Poll DescribeTypeRegistration out of IN_PROGRESS. RAISES on timeout rather than returning the
    last value, so a hung registration is never read as a verdict."""
    deadline = time.monotonic() + REGISTRATION_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_type_registration(RegistrationToken=token)
        if last["ProgressStatus"] != "IN_PROGRESS":
            return last
        time.sleep(5.0)
    raise AssertionError(
        f"type registration {token!r} never left IN_PROGRESS within {REGISTRATION_TIMEOUT_S}s "
        f"(last={last!r})"
    )


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because a target
    ACCEPTING a request real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _delete_bucket(s3, bucket: str) -> None:
    """Empty then delete -- a non-empty bucket refuses deletion, and this one always has an object."""
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for group in ("Versions", "DeleteMarkers"):
                for obj in page.get(group, []) or []:
                    s3.delete_object(Bucket=bucket, Key=obj["Key"], VersionId=obj["VersionId"])
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents", []) or []:
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
