"""instance-task-error-semantics."""
from __future__ import annotations

from botocore.exceptions import ClientError, ParamValidationError

from behavioral_harness import tags

CHECK = "instance-task-error-semantics"
GROUP = 'error-semantics'
SERVICES = ['ec2']

# Well-formed but never-issued resource ids (17 hex chars after the prefix), so
# probes exercise NotFound semantics rather than id-format rejection.
_ABSENT = {
    "subnet": "subnet-0123456789abcdef0",
    "eice": "eice-0123456789abcdef0",
    "instance": "i-0123456789abcdef0",
    "iew": "iew-0123456789abcdef0",
}


def _probe_errors(ec2, probes):
    """Assert a batch of operations all fail with an expected error code.

    *probes* is a list of ``(client_method, kwargs, acceptable_codes)``. Every
    mismatch is collected rather than raising on the first one, so a single run
    reports the real code for every probe. Operations the installed botocore
    does not know about are skipped rather than exploding.
    """
    problems: list[str] = []
    for method, kwargs, expected in probes:
        fn = getattr(ec2, method, None)
        if fn is None:
            continue
        try:
            fn(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in expected:
                problems.append(f"{method}: expected {sorted(expected)}, got {code}")
        except ParamValidationError as exc:
            problems.append(f"{method}: PARAM VALIDATION: {exc}")
        else:
            problems.append(f"{method}: expected {sorted(expected)} but the call SUCCEEDED")
    return problems


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Instance-scoped task operations must reject unknown instance/endpoint ids."""
    ec2 = ctx.client("ec2")
    s3 = ctx.client("s3")
    a = _ABSENT

    # A real bucket, so the InstanceId is the ONLY absent input in the export-task
    # probe below — a nonexistent S3Bucket makes AWS reject on the bucket before it
    # ever looks at InstanceId, which would test the wrong thing.
    bucket = ctx.unique_name("sim2real-behav-export-").lower()
    if ctx.region == "us-east-1":
        # us-east-1 is CreateBucket's own long-standing special case: passing any
        # CreateBucketConfiguration there (even one naming us-east-1 itself) is
        # rejected, so the literal names that one exception, not a target region.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "Name", "Value": bucket}]})

    problems = _probe_errors(ec2, [
        (
            "create_instance_connect_endpoint",
            {"SubnetId": a["subnet"]},
            ("InvalidSubnetID.NotFound",),
        ),
        (
            "delete_instance_connect_endpoint",
            {"InstanceConnectEndpointId": a["eice"]},
            ("InvalidInstanceConnectEndpointId.NotFound",),
        ),
        (
            "create_instance_export_task",
            {
                "InstanceId": a["instance"],
                "TargetEnvironment": "vmware",
                "ExportToS3Task": {
                    "DiskImageFormat": "VMDK",
                    "ContainerFormat": "ova",
                    "S3Bucket": bucket,
                },
            },
            # Empirical: with a real bucket (so InstanceId is the only absent
            # input), real AWS rejects this call with InvalidParameter, not
            # InvalidInstanceID.NotFound -- CreateInstanceExportTask validates
            # instance eligibility as a parameter check, not an existence lookup.
            ("InvalidParameter",),
        ),
        (
            "create_replace_root_volume_task",
            {"InstanceId": a["instance"]},
            # Empirical: unlike the other probes here, CreateReplaceRootVolumeTask
            # rejects this well-formed-but-absent id as malformed, not as not-found.
            ("InvalidInstanceID.Malformed",),
        ),
        (
            "delete_instance_event_window",
            {"InstanceEventWindowId": a["iew"]},
            # Empirical: this code contains no dot separators.
            ("InvalidInstanceEventWindowIDNotFound",),
        ),
    ])
    assert not problems, "unexpected instance-task error semantics:\n" + "\n".join(problems)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
