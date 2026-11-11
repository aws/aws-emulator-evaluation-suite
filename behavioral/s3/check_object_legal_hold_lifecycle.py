"""object-legal-hold-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "object-legal-hold-lifecycle"
GROUP = "state-machine"
SERVICES = ["s3"]
LOCKED_MESSAGE = 'Access Denied because object protected by object lock.'
NO_SUCH_VERSION_MESSAGE = 'The specified version does not exist.'


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutObjectLegalHold toggles ON/OFF and GetObjectLegalHold reflects the current
    hold status at each step (an object with an ON hold cannot be deleted until it is
    switched back OFF)."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-legalhold-")
    key = "legal-hold-test.txt"
    _create_bucket(ctx, s3, name, ObjectLockEnabledForBucket=True)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "project", "Value": "sim2real"}]})

    s3.put_object(Bucket=name, Key=key, Body=b"legal-hold-payload")
    versions = s3.list_object_versions(Bucket=name, Prefix=key)["Versions"]
    version_id = versions[0]["VersionId"]

    s3.put_object_legal_hold(Bucket=name, Key=key, LegalHold={"Status": "ON"})
    got = s3.get_object_legal_hold(Bucket=name, Key=key)
    assert got["LegalHold"]["Status"] == "ON", got

    # While the hold is ON, deletion of that specific object *version* must be
    # blocked (a plain, version-less DeleteObject would merely add a delete
    # marker and is not blocked by a legal hold, so we must target the
    # version explicitly to observe the protection).
    code, message = _error(
        lambda: s3.delete_object(
            Bucket=name, Key=key, VersionId=version_id, BypassGovernanceRetention=True
        )
    )
    assert code == "AccessDenied", f"expected AccessDenied deleting a held version, got {code!r}"
    assert message == LOCKED_MESSAGE, f"unexpected AccessDenied message: {message!r}"

    # the forbidden effect did not happen: the version is still there, readable
    body = s3.get_object(Bucket=name, Key=key, VersionId=version_id)["Body"].read()
    assert body == b"legal-hold-payload", f"expected version to survive the blocked delete, got body {body!r}"

    s3.put_object_legal_hold(Bucket=name, Key=key, LegalHold={"Status": "OFF"})
    got2 = s3.get_object_legal_hold(Bucket=name, Key=key)
    assert got2["LegalHold"]["Status"] == "OFF", got2

    # Now deletion of that specific version succeeds, and an independent read
    # (a different operation than the one that mutated) proves it is really gone.
    s3.delete_object(Bucket=name, Key=key, VersionId=version_id)
    not_found, not_found_message = _error(lambda: s3.get_object(Bucket=name, Key=key, VersionId=version_id))
    assert not_found == "NoSuchVersion", f"expected NoSuchVersion after the real delete, got {not_found!r}"
    assert not_found_message == NO_SUCH_VERSION_MESSAGE, f"unexpected NoSuchVersion message: {not_found_message!r}"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_bucket(ctx, s3, name: str, **kwargs) -> None:
    params: dict = {"Bucket": name}
    # us-east-1 is S3's API-level default region and must NOT be passed as a
    # LocationConstraint (real S3 rejects that combination); every other region must be.
    if ctx.region and ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)


def _empty_and_delete_bucket(s3, name: str, bypass_governance: bool = False) -> None:
    try:
        # Legal holds must be cleared before versions can be deleted.
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=name):
            for v in page.get("Versions", []):
                try:
                    s3.put_object_legal_hold(
                        Bucket=name, Key=v["Key"], VersionId=v["VersionId"], LegalHold={"Status": "OFF"}
                    )
                except ClientError as exc:
                    if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                        raise
        for page in paginator.paginate(Bucket=name):
            to_delete = []
            for v in page.get("Versions", []):
                to_delete.append({"Key": v["Key"], "VersionId": v["VersionId"]})
            for m in page.get("DeleteMarkers", []):
                to_delete.append({"Key": m["Key"], "VersionId": m["VersionId"]})
            if to_delete:
                kwargs = {"Bucket": name, "Delete": {"Objects": to_delete}}
                if bypass_governance:
                    kwargs["BypassGovernanceRetention"] = True
                failed = s3.delete_objects(**kwargs).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
