"""client-token-reuse-conflict-create-application."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "client-token-reuse-conflict-create-application"
GROUP = "error-semantics"
SERVICES = ["gameliftstreams"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Replaying a ClientToken with identical parameters is idempotent (returns the same
    resource); replaying it with a different Description conflicts, and the original
    resource's Description is left unmodified."""
    gl = ctx.client("gameliftstreams")
    s3 = ctx.client("s3")
    token = uuid.uuid4().hex + uuid.uuid4().hex  # 64 chars, within the 32-128 bound
    desc1 = ctx.unique_name("sim2real-behav-gls-tok-a-")
    runtime = {"Type": "UBUNTU", "Version": "22_04_LTS"}
    exec_path = "start.sh"
    creation_tags = {"sim2real-env": "test"}

    bucket = ctx.unique_name("sim2real-behav-glsbkt-")
    try:
        if ctx.region == "us-east-1":
            # us-east-1 rejects CreateBucket if a LocationConstraint is supplied at all.
            s3.create_bucket(Bucket=bucket)
        else:
            s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
        ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
        s3.put_object(Bucket=bucket, Key="build/start.sh", Body=b"#!/bin/sh\necho hi\n")
        ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key="build/start.sh"))
    except ClientError as e:
        raise AssertionError(
            f"S3 write access unavailable in this verification session ({e}); cannot "
            "provision real application content for CreateApplication to succeed on"
        )
    source_uri = f"s3://{bucket}/build"

    first = gl.create_application(
        ClientToken=token,
        Description=desc1,
        RuntimeEnvironment=runtime,
        ExecutablePath=exec_path,
        ApplicationSourceUri=source_uri,
        Tags=creation_tags,
    )
    arn = first["Arn"]
    ctx.on_cleanup(lambda: _delete_application_when_settled(gl, arn))

    # Positive control: replaying the exact same request with the same token is idempotent.
    replay = gl.create_application(
        ClientToken=token,
        Description=desc1,
        RuntimeEnvironment=runtime,
        ExecutablePath=exec_path,
        ApplicationSourceUri=source_uri,
        Tags=creation_tags,
    )
    assert replay["Arn"] == arn, "idempotent replay with identical params should return the same resource"

    # Break exactly one thing: reuse the token with a different Description.
    desc2 = ctx.unique_name("sim2real-behav-gls-tok-b-")
    code, message = _error_code(
        lambda: gl.create_application(
            ClientToken=token,
            Description=desc2,
            RuntimeEnvironment=runtime,
            ExecutablePath=exec_path,
            ApplicationSourceUri=source_uri,
            Tags=creation_tags,
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    expected = "'ClientToken' value has already been used with different request parameters"
    assert _without_internal_id(message) == expected, f"expected {expected!r}, got {message!r}"

    # Effect absent: the original resource's Description was not mutated by the conflicting call.
    fetched = gl.get_application(Identifier=arn)
    assert fetched["Description"] == desc1, (
        f"conflicting create must not mutate the original resource: expected Description "
        f"{desc1!r}, got {fetched['Description']!r}"
    )

    # Restore: the identical original request is still idempotently accepted after the
    # rejected conflict, proving the conflict did not poison the token or the resource.
    restored = gl.create_application(
        ClientToken=token,
        Description=desc1,
        RuntimeEnvironment=runtime,
        ExecutablePath=exec_path,
        ApplicationSourceUri=source_uri,
        Tags=creation_tags,
    )
    assert restored["Arn"] == arn, (
        "identical original request must still succeed idempotently after the rejected "
        "conflicting reuse"
    )

    # Independent terminal read: confirm via GetApplication (not CreateApplication's own
    # response) that the restored resource still carries the original Description.
    final = gl.get_application(Identifier=arn)
    assert final["Description"] == desc1, (
        f"expected {desc1!r} still associated with {arn!r} after the idempotent restore, got "
        f"{final['Description']!r}"
    )


def _error_code(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _without_internal_id(message):
    """GameLift Streams ends every error message with a per-request "(Internal ID: <uuid>)"."""
    stable, sep, rest = message.rpartition(" (Internal ID: ")
    assert sep and rest.endswith(")"), f"expected a trailing '(Internal ID: ...)', got {message!r}"
    return stable


def _delete_application_when_settled(gl, arn, timeout_s=300.0):
    """DeleteApplication refuses an application that is still INITIALIZED or PROCESSING."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            gl.delete_application(Identifier=arn)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ValidationException" or time.monotonic() >= deadline:
                raise
        time.sleep(5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
