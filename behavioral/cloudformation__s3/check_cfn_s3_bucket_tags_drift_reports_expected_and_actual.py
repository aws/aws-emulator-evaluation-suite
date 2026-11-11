"""cfn-s3-bucket-tags-drift-reports-expected-and-actual."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-s3-bucket-tags-drift-reports-expected-and-actual"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3"]

_TAG_KEY = "sim2real-env"
_TEMPLATE_VALUE = "template"
_DRIFTED_VALUE = "drifted"
_WAITER_DELAY_S = 2
_WAITER_ATTEMPTS = 150
_DETECT_TIMEOUT_S = 180.0
_POLL_INTERVAL_S = 2.0
_PROPAGATE_TIMEOUT_S = 120.0


@tags(
    "axis:happy-path",
    "concern:deploy",
    "concern:representation",
    "plane:control",
    "cap:c3",
    "cap:c4",
)
def run(ctx) -> None:
    """DetectStackDrift on a stack whose S3 bucket tag value changed out of band reports the
    stack DRIFTED, and DescribeStackResourceDrifts names the tag's property path with the
    template and live values; deleting the stack removes the bucket.
    """
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    stack_name = ctx.unique_name("sim2real-cfn-s3drift-")

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name,
        WaiterConfig={"Delay": _WAITER_DELAY_S, "MaxAttempts": _WAITER_ATTEMPTS},
    )
    created = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    assert created == "CREATE_COMPLETE", f"stack {stack_name!r}: expected CREATE_COMPLETE, got {created!r}"

    bucket_name = cfn.describe_stack_resource(StackName=stack_name, LogicalResourceId="Bucket")[
        "StackResourceDetail"
    ]["PhysicalResourceId"]

    # Beat 1: positive control — a freshly created stack must detect as IN_SYNC.
    clean = _detect(cfn, stack_name)
    assert clean["StackDriftStatus"] == "IN_SYNC", (
        f"a freshly created stack must detect as IN_SYNC, got {clean['StackDriftStatus']!r} "
        f"({clean.get('DriftedStackResourceCount')!r} drifted)"
    )

    # Beat 2: change exactly one property, out of band, through S3's own API. CloudFormation's
    # own aws:cloudformation:* system tags must be echoed back unchanged, or PutBucketTagging
    # rejects the call as removing them.
    current = s3.get_bucket_tagging(Bucket=bucket_name)["TagSet"]
    new_set = [t if t["Key"] != _TAG_KEY else {"Key": _TAG_KEY, "Value": _DRIFTED_VALUE} for t in current]
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": new_set})
    _await_tag(s3, bucket_name, _TAG_KEY, _DRIFTED_VALUE)

    # Beat 3: drift must name the path, the type, and both values.
    drifted = _detect(cfn, stack_name)
    assert drifted["StackDriftStatus"] == "DRIFTED", (
        f"stack drift status: expected DRIFTED, got {drifted['StackDriftStatus']!r}"
    )
    assert drifted["DriftedStackResourceCount"] == 1, (
        f"exactly one resource drifted, so DriftedStackResourceCount must be 1, got "
        f"{drifted['DriftedStackResourceCount']!r}"
    )
    drifts = {d["LogicalResourceId"]: d for d in _resource_drifts(cfn, stack_name)}
    bucket_drift = drifts.get("Bucket")
    assert bucket_drift, f"drift reported nothing for Bucket: {sorted(drifts)}"
    assert bucket_drift["StackResourceDriftStatus"] == "MODIFIED", (
        f"the out-of-band change must be reported MODIFIED, got "
        f"{bucket_drift['StackResourceDriftStatus']!r}"
    )
    diffs = [
        d
        for d in bucket_drift.get("PropertyDifferences", [])
        if d["PropertyPath"] == "/Tags/0/Value"
    ]
    assert len(diffs) == 1, f"no single /Tags/0/Value PropertyDifference: {bucket_drift.get('PropertyDifferences')!r}"
    diff = diffs[0]
    assert diff["DifferenceType"] == "NOT_EQUAL", (
        f"DifferenceType: expected NOT_EQUAL for a changed scalar, got {diff['DifferenceType']!r}"
    )
    assert diff["ExpectedValue"] == _TEMPLATE_VALUE, (
        f"ExpectedValue must be the TEMPLATE value {_TEMPLATE_VALUE!r}, got {diff['ExpectedValue']!r}"
    )
    assert diff["ActualValue"] == _DRIFTED_VALUE, (
        f"ActualValue must be the LIVE value {_DRIFTED_VALUE!r}, got {diff['ActualValue']!r}"
    )

    # Beat 4: delete the stack in band and confirm the bucket is gone through S3's own API.
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name,
        WaiterConfig={"Delay": _WAITER_DELAY_S, "MaxAttempts": _WAITER_ATTEMPTS},
    )
    code, message = _error_code(lambda: s3.get_bucket_tagging(Bucket=bucket_name))
    assert (code, message) == ("NoSuchBucket", "The specified bucket does not exist"), (
        f"expected the bucket gone with NoSuchBucket 'The specified bucket does not exist', got "
        f"{(code, message)!r}"
    )


def _template() -> str:
    """One S3 bucket with a hardcoded tag value the check will drift."""
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Bucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {"Tags": [{"Key": _TAG_KEY, "Value": _TEMPLATE_VALUE}]},
                }
            },
        }
    )


def _error_code(fn) -> tuple[str, str]:
    """The (Error.Code, Error.Message) ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _await_tag(s3, bucket_name: str, key: str, want: str) -> None:
    """S3 tag writes can lag the call that made them; poll before detecting drift."""
    deadline = time.monotonic() + _PROPAGATE_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        tags_now = {t["Key"]: t["Value"] for t in s3.get_bucket_tagging(Bucket=bucket_name)["TagSet"]}
        last = tags_now.get(key)
        if last == want:
            return
        time.sleep(_POLL_INTERVAL_S)
    raise AssertionError(
        f"bucket {bucket_name!r} tag {key!r} never became {want!r} within "
        f"{_PROPAGATE_TIMEOUT_S}s (last={last!r})"
    )


def _detect(cfn, stack_name: str) -> dict:
    """Run one drift detection to completion and return its status record. RAISES on timeout."""
    detection_id = cfn.detect_stack_drift(StackName=stack_name)["StackDriftDetectionId"]
    deadline = time.monotonic() + _DETECT_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stack_drift_detection_status(StackDriftDetectionId=detection_id)
        if last["DetectionStatus"] in {"DETECTION_COMPLETE", "DETECTION_FAILED"}:
            assert last["DetectionStatus"] == "DETECTION_COMPLETE", (
                f"drift detection {detection_id!r} failed: {last.get('DetectionStatusReason')!r}"
            )
            return last
        time.sleep(_POLL_INTERVAL_S)
    raise AssertionError(
        f"drift detection {detection_id!r} did not complete within {_DETECT_TIMEOUT_S}s (last={last!r})"
    )


def _resource_drifts(cfn, stack_name: str) -> list[dict]:
    out: list[dict] = []
    token = None
    while True:
        kw = {"StackName": stack_name}
        if token:
            kw["NextToken"] = token
        page = cfn.describe_stack_resource_drifts(**kw)
        out.extend(page["StackResourceDrifts"])
        token = page.get("NextToken")
        if not token:
            return out


def _delete_stack_and_wait(cfn, stack_name: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 25}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
