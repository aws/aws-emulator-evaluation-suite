"""e2e-ota-update-package-job-delivery."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "e2e-ota-update-package-job-delivery"
GROUP = "e2e"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data", "resource:account-singleton:iot-indexing")
def run(ctx) -> None:
    """End-to-end: publish a package version, create an OTA update job referencing
    it, a thing fetches the job document and reports success, then deleting the OTA
    update and package version leaves no residual state."""
    iot = ctx.client("iot")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    bucket = ctx.unique_name("sim2real-iot-ota-").lower().replace("_", "-")
    key = "firmware.bin"
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket, key))
    s3.put_object(Bucket=bucket, Key=key, Body=b"sim2real-fake-firmware-bytes-v1")

    role_name = ctx.unique_name("sim2real-iot-ota-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "iot.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSIoTOTAUpdate")
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSIoTOTAUpdate"))
    # AFR_OTA-<otaUpdateId> is the job the OTA service creates per attempt (a fresh
    # otaUpdateId per retry in _create_ota_until_ready); scope to this check's own prefix.
    job_arn_pattern = f"arn:aws:iot:{ctx.region}:{account_id}:job/AFR_OTA-sim2real-ota-*"
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:GetBucketLocation"], "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"]},
            # The OTA service assumes this role, then that assumed-role session itself calls
            # CreateJob and must PassRole on the same role again -- real AWS rejects
            # CreateOTAUpdate with an AccessDeniedException on iam:PassRole without this.
            {"Effect": "Allow", "Action": "iam:PassRole", "Resource": role_arn},
            # DeleteOTAUpdate(forceDeleteAWSJob=True) likewise has the OTA service assume this
            # role to delete the underlying Job -- real AWS rejects it with AccessDeniedException
            # on iot:DeleteJob without this (the AWSIoTOTAUpdate managed policy doesn't cover it).
            {"Effect": "Allow", "Action": "iot:DeleteJob", "Resource": job_arn_pattern},
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="sim2real-ota-inline", PolicyDocument=json.dumps(inline_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-ota-inline"))

    package_name = ctx.unique_name("sim2real-pkg-")
    _enable_package_fleet_indexing(iot, ctx)
    _create_package_with_retry(iot, package_name)
    ctx.on_cleanup(lambda: iot.delete_package(packageName=package_name))
    version_name = "1.0.0"
    iot.create_package_version(packageName=package_name, versionName=version_name)
    iot.update_package_version(packageName=package_name, versionName=version_name, action="PUBLISH")
    published = iot.get_package_version(packageName=package_name, versionName=version_name)
    assert published["status"] == "PUBLISHED", f"expected PUBLISHED, got {published['status']!r}"

    thing_name = ctx.unique_name("sim2real-iot-thing-")
    thing_arn = iot.create_thing(thingName=thing_name)["thingArn"]
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))

    final_ota = _create_ota_until_ready(
        iot,
        ctx,
        targets=[thing_arn],
        targetSelection="SNAPSHOT",
        protocols=["HTTP"],
        files=[{"fileName": key, "fileVersion": version_name, "fileLocation": {"s3Location": {"bucket": bucket, "key": key}}}],
        roleArn=role_arn,
        additionalParameters={"packageName": package_name, "packageVersionName": version_name},
    )
    assert final_ota["otaUpdateStatus"] == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {final_ota['otaUpdateStatus']!r} "
        f"(errorInfo={final_ota.get('errorInfo')})"
    )
    ota_id = final_ota["otaUpdateId"]
    job_id = final_ota["awsIotJobId"]

    document = iot.get_job_document(jobId=job_id)["document"]
    parsed_document = json.loads(document)
    assert isinstance(parsed_document, dict) and parsed_document, f"expected a non-empty job document, got {document!r}"
    assert key in document, f"expected file key {key!r} in job document, got {document!r}"  # the S3 object key shows up in the file entry / presigned URL

    # CREATE_COMPLETE on the OTA update means the underlying Job exists, but the per-thing
    # JobExecution row it fans out to is populated asynchronously -- an immediate
    # UpdateJobExecution can race it with a ResourceNotFoundException ("Job ... not found for
    # ..."). Wait for the execution to become queryable before driving it.
    _wait_for_job_execution(iot, job_id, thing_name)

    # UpdateJobExecution (classic Jobs data plane) is likewise served through the
    # unified iot:Data-ATS endpoint via the "iot-jobs-data" client.
    jobs_endpoint = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    jobs_data = ctx.client("iot-jobs-data", endpoint_url=ctx.endpoint_url(jobs_endpoint))
    jobs_data.update_job_execution(jobId=job_id, thingName=thing_name, status="SUCCEEDED")

    final_execution = _poll_until(
        lambda: iot.describe_job_execution(jobId=job_id, thingName=thing_name)["execution"],
        lambda execution: execution["status"] in ("SUCCEEDED", "FAILED", "REJECTED", "TIMED_OUT"),
        timeout_s=30.0,
        reason="job execution to reach a terminal status after UpdateJobExecution(SUCCEEDED)",
    )
    assert final_execution["status"] == "SUCCEEDED", f"expected SUCCEEDED, got {final_execution['status']!r}"

    iot.delete_ota_update(otaUpdateId=ota_id, deleteStream=True, forceDeleteAWSJob=True)
    code, message = _wait_for_not_found(lambda: iot.get_ota_update(otaUpdateId=ota_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException reading deleted OTA update, got {code!r}"
    expected = f"Requested otaUpdateJob {ota_id} does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    code, message = _error_code(lambda: iot.delete_ota_update(otaUpdateId=ota_id, deleteStream=True, forceDeleteAWSJob=True))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException re-deleting the dead OTA update, got {code!r}"
    expected = f"Requested otaUpdateJob {ota_id} does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    iot.delete_package_version(packageName=package_name, versionName=version_name)
    code, message = _wait_for_not_found(lambda: iot.get_package_version(packageName=package_name, versionName=version_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException reading deleted package version, got {code!r}"
    expected_version_gone = f"PackageVersion {version_name} for package {package_name} not found"
    assert message == expected_version_gone, f"expected message {expected_version_gone!r}, got {message!r}"
    # Unlike DeleteOTAUpdate (which 404s on a repeat), DeletePackageVersion is idempotent on
    # real AWS: re-deleting an already-gone version succeeds rather than raising.
    iot.delete_package_version(packageName=package_name, versionName=version_name)
    code, message = _error_code(lambda: iot.get_package_version(packageName=package_name, versionName=version_name))
    assert code == "ResourceNotFoundException", f"expected the version to remain gone after a redundant delete, got {code!r}"
    assert message == expected_version_gone, f"expected message {expected_version_gone!r}, got {message!r}"


def _create_ota_until_ready(iot, ctx, attempts=6, delay_s=10.0, **kwargs):
    """CreateOTAUpdate itself succeeds immediately, but the OTA service asynchronously
    assumes roleArn afterward; a just-created IAM role's trust policy can still be
    propagating, producing a CREATE_FAILED/InvalidRequestException ("Permission denied
    when attempting to assume role ..."). Retry the whole create+poll-to-terminal cycle
    (with a fresh OTA id each time, cleaning up the failed attempt) until it succeeds."""
    last_info = None
    for _ in range(attempts):
        ota_id = ctx.unique_name("sim2real-ota-")
        iot.create_ota_update(otaUpdateId=ota_id, **kwargs)
        ctx.on_cleanup(lambda oid=ota_id: _try_delete_ota(iot, oid))

        info = _poll_until(
            lambda oid=ota_id: iot.get_ota_update(otaUpdateId=oid)["otaUpdateInfo"],
            lambda info: info["otaUpdateStatus"] in ("CREATE_COMPLETE", "CREATE_FAILED"),
            timeout_s=60.0,
            reason=f"OTA update {ota_id} to reach a terminal create status",
        )
        last_info = info
        if info["otaUpdateStatus"] == "CREATE_COMPLETE":
            return info
        error_msg = info.get("errorInfo", {}).get("message", "")
        if "assume role" not in error_msg.lower() and "not authorized" not in error_msg.lower():
            break  # a non-propagation failure -- retrying won't help
        _try_delete_ota(iot, ota_id)
        time.sleep(delay_s)
    return last_info


def _wait_for_job_execution(iot, job_id, thing_name, timeout_s=60.0, interval_s=2.0):
    """The Job's per-thing JobExecution fans out asynchronously after the Job itself exists;
    poll describe_job_execution until it stops answering ResourceNotFoundException."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return iot.describe_job_execution(jobId=job_id, thingName=thing_name)["execution"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(
        f"job execution for thing {thing_name!r} on job {job_id!r} never became queryable within {timeout_s}s"
    ) from last_exc


def _try_delete_ota(iot, ota_id):
    """Delete an OTA update; an already-deleted one (ResourceNotFoundException) is clean."""
    try:
        iot.delete_ota_update(otaUpdateId=ota_id, deleteStream=True, forceDeleteAWSJob=True)
    except iot.exceptions.ResourceNotFoundException:
        pass


def _enable_package_fleet_indexing(iot, ctx):
    """CreatePackage fails with ValidationException ("Enable fleet indexing for
    '$package' named shadow.") unless the account's fleet indexing is configured to
    index the reserved $package named shadow -- a prerequisite documented for
    Software Package Catalog. Enable it (saving the prior config to restore after)."""
    existing = iot.get_indexing_configuration()
    original_thing_cfg = existing.get("thingIndexingConfiguration")

    def _restore():
        if original_thing_cfg:
            iot.update_indexing_configuration(thingIndexingConfiguration=original_thing_cfg)
        else:
            iot.update_indexing_configuration(thingIndexingConfiguration={"thingIndexingMode": "OFF"})

    ctx.on_cleanup(_restore)
    current_mode = (original_thing_cfg or {}).get("thingIndexingMode")
    new_mode = current_mode if current_mode and current_mode != "OFF" else "REGISTRY"
    iot.update_indexing_configuration(
        thingIndexingConfiguration={
            "thingIndexingMode": new_mode,
            "namedShadowIndexingMode": "ON",
            "filter": {"namedShadowNames": ["$package"]},
        }
    )


def _create_package_with_retry(iot, package_name, attempts=10, delay_s=5.0):
    """Fleet-indexing configuration changes are eventually consistent; poll until
    CreatePackage stops rejecting for the missing-indexing precondition."""
    last_exc = None
    for _ in range(attempts):
        try:
            iot.create_package(packageName=package_name)
            return
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc



def _delete_bucket(s3, bucket, key):
    """Teardown: empty and delete the bucket; only NoSuchBucket counts as already clean."""
    try:
        s3.delete_object(Bucket=bucket, Key=key)
        s3.delete_bucket(Bucket=bucket)
    except s3.exceptions.NoSuchBucket:
        pass


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0, reason="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {reason}; last saw {last!r}")


def _error_code(fn):
    """Call fn(); return the botocore (error code, error message). An unexpected SUCCESS
    raises, so an accepted call fails clearly as an acceptance."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _wait_for_not_found(fn, timeout_s=60.0, interval_s=2.0):
    """Delete is asynchronous: an immediate read after DeleteOTAUpdate/DeletePackageVersion can
    still succeed and report a DELETE_IN_PROGRESS-style transitional status. Poll fn() (a thunk
    making the read) until it raises ResourceNotFoundException, tolerating that transient window,
    and return that error's (code, message)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == "ResourceNotFoundException":
                return err.get("Code"), err.get("Message")
            raise
        time.sleep(interval_s)
    raise AssertionError(f"resource did not become not-found within {timeout_s}s; last read returned {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
