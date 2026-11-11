"""s3-object-lock-compliance-cannot-be-bypassed-while-governance-can."""

from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-object-lock-compliance-cannot-be-bypassed-while-governance-can"
GROUP = 'object-lock-rejection'
SERVICES = ['s3']

_PAYLOAD_COMPLIANCE = b"compliance-locked-bytes-no-principal-may-delete-early"
_PAYLOAD_GOVERNANCE = b"governance-locked-bytes-a-bypass-may-remove"

#: No principal, including the account root, may delete a COMPLIANCE version before its date, so
#: the retention is kept short and the teardown polls the delete until it lapses.
_RETAIN_S = 75
_TEARDOWN_BUDGET_S = 240.0
_TEARDOWN_POLL_S = 10.0


def _delete_locked_bucket(client, bucket):
    """Empty and delete an Object Lock bucket, waiting out any surviving COMPLIANCE retention.

    A COMPLIANCE version refuses DeleteObject until RetainUntilDate, and blocks DeleteBucket.
    """
    deadline = time.monotonic() + _TEARDOWN_BUDGET_S
    while True:
        remaining = []
        try:
            for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
                for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                    try:
                        client.delete_object(
                            Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"],
                            BypassGovernanceRetention=True,
                        )
                    except ClientError as exc:
                        if exc.response["Error"]["Code"] != "AccessDenied":  # retention not yet lapsed
                            raise
                        remaining.append((o["Key"], o["VersionId"]))
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise
            break
        if not remaining or time.monotonic() >= deadline:
            break
        time.sleep(_TEARDOWN_POLL_S)
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _client_error(fn):
    """Call fn(); return the ClientError it raised, or None if it returned normally."""
    try:
        fn()
    except ClientError as exc:
        return exc
    return None


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """The same BypassGovernanceRetention DeleteObject is refused AccessDenied for a COMPLIANCE version
    (bytes intact) and succeeds for a GOVERNANCE version (gone) in the same bucket.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html
    """
    s3 = ctx.client("s3")

    # ObjectLockEnabledForBucket implies versioning, which object lock requires.
    bucket = ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": bucket, "ObjectLockEnabledForBucket": True}
    # us-east-1 is the one region CreateBucket rejects with InvalidLocationConstraint if a
    # LocationConstraint is supplied at all, so it is the one literal region check omitted here.
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    # Registered before any assertion: this bucket's deletion is time-gated by the retention.
    ctx.on_cleanup(lambda: _delete_locked_bucket(s3, bucket))

    assert s3.get_bucket_versioning(Bucket=bucket).get("Status") == "Enabled", (
        "ObjectLockEnabledForBucket did not implicitly enable versioning"
    )
    lock_conf = s3.get_object_lock_configuration(Bucket=bucket)["ObjectLockConfiguration"]
    assert lock_conf.get("ObjectLockEnabled") == "Enabled", (
        f"the bucket's object lock configuration is {lock_conf!r}, want ObjectLockEnabled=Enabled"
    )

    now = datetime.datetime.now(datetime.timezone.utc)
    compliance_until = now + datetime.timedelta(seconds=_RETAIN_S)
    governance_until = now + datetime.timedelta(minutes=30)

    compliance_version = s3.put_object(
        Bucket=bucket, Key="compliance.bin", Body=_PAYLOAD_COMPLIANCE
    )["VersionId"]
    s3.put_object_retention(
        Bucket=bucket, Key="compliance.bin", VersionId=compliance_version,
        Retention={"Mode": "COMPLIANCE", "RetainUntilDate": compliance_until},
    )
    governance_version = s3.put_object(
        Bucket=bucket, Key="governance.bin", Body=_PAYLOAD_GOVERNANCE
    )["VersionId"]
    s3.put_object_retention(
        Bucket=bucket, Key="governance.bin", VersionId=governance_version,
        Retention={"Mode": "GOVERNANCE", "RetainUntilDate": governance_until},
    )

    compliance_retention = s3.get_object_retention(
        Bucket=bucket, Key="compliance.bin", VersionId=compliance_version
    )["Retention"]
    assert compliance_retention["Mode"] == "COMPLIANCE", (
        f"the compliance version's retention reads {compliance_retention!r}"
    )
    governance_retention = s3.get_object_retention(
        Bucket=bucket, Key="governance.bin", VersionId=governance_version
    )["Retention"]
    assert governance_retention["Mode"] == "GOVERNANCE", (
        f"the governance version's retention reads {governance_retention!r}"
    )

    refused = _client_error(lambda: s3.delete_object(
        Bucket=bucket, Key="compliance.bin", VersionId=compliance_version,
        BypassGovernanceRetention=True,
    ))
    assert refused is not None, (
        "DeleteObject with BypassGovernanceRetention=True removed a COMPLIANCE-retained version. "
        "COMPLIANCE is unbypassable by every principal including the account root until its "
        "RetainUntilDate — an emulator that honours the bypass flag here voids the entire "
        "write-once compliance guarantee its users are relying on"
    )
    code = refused.response.get("Error", {}).get("Code")
    message = refused.response.get("Error", {}).get("Message")
    status = refused.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert code == "AccessDenied", (
        f"expected AccessDenied for a bypass delete of a COMPLIANCE version, got {code!r}"
    )
    assert message == "Access Denied because object protected by object lock.", (
        f"the COMPLIANCE refusal's message is {message!r}, want "
        "'Access Denied because object protected by object lock.'"
    )
    assert status == 403, f"expected HTTP 403, got {status!r}"

    intact = s3.get_object(
        Bucket=bucket, Key="compliance.bin", VersionId=compliance_version
    )["Body"].read()
    assert intact == _PAYLOAD_COMPLIANCE, (
        f"the refused delete damaged the compliance object: it holds {intact!r}, want "
        f"{_PAYLOAD_COMPLIANCE!r}"
    )
    assert s3.get_object_retention(
        Bucket=bucket, Key="compliance.bin", VersionId=compliance_version
    )["Retention"]["Mode"] == "COMPLIANCE", (
        "the refused delete altered the compliance version's retention mode"
    )

    bypassed = s3.delete_object(
        Bucket=bucket, Key="governance.bin", VersionId=governance_version,
        BypassGovernanceRetention=True,
    )
    assert bypassed["ResponseMetadata"]["HTTPStatusCode"] == 204, (
        f"the governance bypass delete returned "
        f"{bypassed['ResponseMetadata']['HTTPStatusCode']!r}, expected 204 — GOVERNANCE retention "
        "IS bypassable and refusing it makes the two modes indistinguishable"
    )
    assert bypassed.get("VersionId") == governance_version, (
        f"the bypass delete reported VersionId {bypassed.get('VersionId')!r}, want the targeted "
        f"{governance_version!r}"
    )

    gone = _client_error(lambda: s3.get_object(
        Bucket=bucket, Key="governance.bin", VersionId=governance_version
    ))
    assert gone is not None, (
        "the governance bypass delete reported success but the version is still readable"
    )
    assert gone.response["ResponseMetadata"]["HTTPStatusCode"] == 404, (
        f"GetObject on the bypassed governance version returned "
        f"{gone.response['ResponseMetadata']['HTTPStatusCode']!r}, expected 404"
    )

    surviving = []
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        surviving += [(v["Key"], v["VersionId"]) for v in page.get("Versions", [])]
    assert surviving == [("compliance.bin", compliance_version)], (
        f"the bucket's surviving versions are {surviving!r}; want exactly the COMPLIANCE one, "
        f"[('compliance.bin', {compliance_version!r})] — the two retention modes did not diverge"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
