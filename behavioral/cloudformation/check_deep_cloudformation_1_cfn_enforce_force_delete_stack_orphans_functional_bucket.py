"""deep-cloudformation-1-cfn-enforce-force-delete-stack-orphans-functional-bucket."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cloudformation-1-cfn-enforce-force-delete-stack-orphans-functional-bucket"
GROUP = "deploy-stack-recovery"
SERVICES = ["cloudformation"]


@tags("plane:control", "cap:c3", "concern:negative-classes", "concern:deploy", "axis:rejection")
def run(ctx) -> None:
    """A stack whose non-empty bucket blocks deletion stays DELETE_FAILED on a plain retry, while
    FORCE_DELETE_STACK reaches DELETE_COMPLETE and orphans a still-usable bucket with its object."""
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")

    stack = ctx.unique_name("sim2real-cfnenf-fd-")
    bucket = stack  # lowercase, digits and hyphens only: a valid bucket name
    template = json.dumps({
        "Resources": {"B": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": bucket}}}
    })

    stack_id = cfn.create_stack(StackName=stack, TemplateBody=template,
                                Tags=[{"Key": "sim2real", "Value": CHECK}])["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    # The orphaned bucket is ours to remove whatever happens to the stack.
    ctx.on_cleanup(lambda: _drop_bucket(s3, bucket))
    st = _wait_terminal(cfn, stack_id)
    assert st["StackStatus"] == "CREATE_COMPLETE", (
        f"bucket stack ended {st['StackStatus']!r} ({st.get('StackStatusReason')!r})"
    )

    payload = b"sim2real force-delete probe\n"
    s3.put_object(Bucket=bucket, Key="pin.txt", Body=payload)

    # First delete: the non-empty bucket resists, the stack lands in DELETE_FAILED.
    cfn.delete_stack(StackName=stack_id)
    st = _wait_terminal(cfn, stack_id)
    assert st["StackStatus"] == "DELETE_FAILED", (
        f"deleting a stack whose bucket is non-empty ended {st['StackStatus']!r}, "
        f"expected DELETE_FAILED"
    )
    assert _resource_status(cfn, stack_id, "B") == "DELETE_FAILED", (
        f"bucket resource status {_resource_status(cfn, stack_id, 'B')!r}, expected DELETE_FAILED"
    )

    # Plain retry: accepted, and refused again by re-entering DELETE_FAILED.
    n_before = len(_all_events(cfn, stack_id))
    cfn.delete_stack(StackName=stack_id)
    st = _wait_terminal(cfn, stack_id)
    assert st["StackStatus"] == "DELETE_FAILED", (
        f"a plain DeleteStack retry reached {st['StackStatus']!r}; nothing changed, so it must "
        f"stay DELETE_FAILED"
    )
    events = _all_events(cfn, stack_id)
    new = events[: len(events) - n_before]
    assert any(e["LogicalResourceId"] == "B" and e.get("ResourceStatus") == "DELETE_FAILED"
               for e in new), (
        f"the retry recorded no new DELETE_FAILED for the bucket; new events "
        f"{[(e['LogicalResourceId'], e.get('ResourceStatus')) for e in new]!r}"
    )
    assert s3.get_object(Bucket=bucket, Key="pin.txt")["Body"].read() == payload, (
        "the object vanished during the refused deletes"
    )

    # Force delete converges and abandons the stuck bucket.
    cfn.delete_stack(StackName=stack_id, DeletionMode="FORCE_DELETE_STACK")
    st = _wait_terminal(cfn, stack_id)
    assert st["StackStatus"] == "DELETE_COMPLETE", (
        f"FORCE_DELETE_STACK reached {st['StackStatus']!r} ({st.get('StackStatusReason')!r}), "
        f"expected DELETE_COMPLETE"
    )
    code, message = _error(lambda: cfn.describe_stacks(StackName=stack))
    assert code == "ValidationError", (
        f"describing the force-deleted stack by NAME returned {code!r}, expected ValidationError"
    )
    assert message == f"Stack with id {stack} does not exist", (
        f"describing the force-deleted stack by NAME returned message {message!r}"
    )

    # The orphan is still a working bucket.
    s3.head_bucket(Bucket=bucket)
    body = s3.get_object(Bucket=bucket, Key="pin.txt")["Body"].read()
    assert body == payload, f"orphaned bucket returned {body!r}, expected {payload!r}"
    s3.put_object(Bucket=bucket, Key="after.txt", Body=b"still writable")
    after = s3.get_object(Bucket=bucket, Key="after.txt")["Body"].read()
    assert after == b"still writable", f"write to the orphaned bucket read back {after!r}"



class _Succeeded(Exception):
    """Raised by _error when a call expected to fail succeeds."""


def _error(fn) -> tuple[str, str]:
    """Call fn(); return (code, message) of the ClientError raised."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise _Succeeded("call expected to fail succeeded")


def _drop_bucket(s3, bucket: str) -> None:
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
                s3.delete_object(Bucket=bucket, Key=v["Key"], VersionId=v["VersionId"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise RuntimeError(f"bucket {bucket}: {exc}") from exc


def _delete_stack(cfn, stack_id: str) -> None:
    st = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if st == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    deadline = time.time() + 600
    while time.time() < deadline:
        st = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if st == "DELETE_COMPLETE":
            return
        if st == "DELETE_FAILED":
            cfn.delete_stack(StackName=stack_id, DeletionMode="FORCE_DELETE_STACK")
        time.sleep(5)
    raise RuntimeError(f"stack {stack_id} did not finish deleting within 600s")


def _wait_terminal(cfn, stack_id: str, timeout: float = 600) -> dict:
    deadline = time.time() + timeout
    while True:
        st = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not st["StackStatus"].endswith("_IN_PROGRESS"):
            return st
        assert time.time() < deadline, (
            f"stack {stack_id} still {st['StackStatus']!r} after {timeout:.0f}s"
        )
        time.sleep(5)


def _all_events(cfn, stack_id: str) -> list[dict]:
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out


def _resource_status(cfn, stack_id: str, logical_id: str) -> str:
    return cfn.describe_stack_resource(
        StackName=stack_id, LogicalResourceId=logical_id
    )["StackResourceDetail"]["ResourceStatus"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
