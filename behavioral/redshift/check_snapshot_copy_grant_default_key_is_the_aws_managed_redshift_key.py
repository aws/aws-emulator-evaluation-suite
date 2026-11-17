"""snapshot-copy-grant-default-key-is-the-aws-managed-redshift-key."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "snapshot-copy-grant-default-key-is-the-aws-managed-redshift-key"
GROUP = "representation"
SERVICES = ["kms", "redshift"]

MANAGED_KEY_ALIAS = "alias/aws/redshift"
_THROTTLE = (
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
)
_NOT_FOUND_GRANT = ("SnapshotCopyGrantNotFoundFault",)


def _code_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _retrying(fn, attempts=6, delay_s=5.0):
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if _code_of(exc) not in _THROTTLE:
                raise
            last = exc
            time.sleep(delay_s * (attempt + 1))
    raise last


def _delete_grant(rs, name):
    try:
        rs.delete_snapshot_copy_grant(SnapshotCopyGrantName=name)
    except ClientError as exc:
        if _code_of(exc) not in _NOT_FOUND_GRANT:
            raise


def _find_grant(rs, name):
    marker = None
    while True:
        kwargs = {"SnapshotCopyGrantName": name, "MaxRecords": 100}
        if marker:
            kwargs["Marker"] = marker
        resp = _retrying(lambda: rs.describe_snapshot_copy_grants(**kwargs))
        for grant in resp.get("SnapshotCopyGrants", []):
            if grant["SnapshotCopyGrantName"] == name:
                return grant
        marker = resp.get("Marker")
        if not marker:
            break
    raise AssertionError(f"snapshot copy grant {name!r} not found by an independent describe")


@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSnapshotCopyGrant with no KmsKeyId grants Amazon Redshift permission on the
    account's AWS-managed alias/aws/redshift key, not a caller-created one.

    Reference: https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html
    """
    rs = ctx.client("redshift")
    kms = ctx.client("kms")

    # The resource AWS creates on first use (never the caller's), looked up by its fixed alias.
    managed_key = kms.describe_key(KeyId=MANAGED_KEY_ALIAS)["KeyMetadata"]
    assert managed_key["KeyManager"] == "AWS", (
        f"{MANAGED_KEY_ALIAS!r} must be an AWS-managed key, got KeyManager={managed_key.get('KeyManager')!r}"
    )

    grant_name = ctx.unique_name("sim2real-behav-rs-defgrant-")
    ctx.on_cleanup(lambda: _delete_grant(rs, grant_name))
    created = _retrying(
        lambda: rs.create_snapshot_copy_grant(
            SnapshotCopyGrantName=grant_name,
            Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
        )
    )["SnapshotCopyGrant"]
    assert created["SnapshotCopyGrantName"] == grant_name, created
    assert created["KmsKeyId"] in (managed_key["Arn"], managed_key["KeyId"]), (
        f"a grant created with no KmsKeyId must use the account's {MANAGED_KEY_ALIAS!r} key "
        f"({managed_key['Arn']!r}); got {created.get('KmsKeyId')!r}"
    )

    # Independent read at the resource's own describe, not the mutating call's own response.
    described = _find_grant(rs, grant_name)
    assert described["KmsKeyId"] == created["KmsKeyId"], (
        f"expected the described grant to report the same key {created['KmsKeyId']!r}, "
        f"got {described.get('KmsKeyId')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
