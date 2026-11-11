"""overly-permissive-package-missing-and-bad-source."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "overly-permissive-package-missing-and-bad-source"
GROUP = 'overly-permissive'
SERVICES = ['opensearch']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListDomainsForPackage and DeletePackage with a malformed package id and CreatePackage from a missing S3
    object each fail with ValidationException and its exact message, while a real package lists and
    deletes.
    """
    os = ctx.client('opensearch')
    s3 = ctx.client('s3')
    malformed_package_id = 'not-a-package-id'

    # ---- positive control: a real package backed by a real, accessible S3 object.
    bucket = ctx.unique_name('sim2real-behav-os-nobucket-').lower()
    region = ctx.region
    if region == 'us-east-1':
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={'LocationConstraint': region})

    def _cleanup_bucket(b=bucket):
        try:
            for obj in s3.list_objects_v2(Bucket=b).get('Contents', []):
                s3.delete_object(Bucket=b, Key=obj['Key'])
            s3.delete_bucket(Bucket=b)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise

    ctx.on_cleanup(_cleanup_bucket)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={'TagSet': [{'Key': 'sim2real', 'Value': CHECK}]})
    key = 'dictionary.txt'
    s3.put_object(Bucket=bucket, Key=key, Body=b'hello\nworld\n')

    good_package_name = ctx.unique_name('sim2real-behav-pkg-good-')
    # A brand-new bucket is not always immediately reachable from the OpenSearch
    # service: CreatePackage rejects the source with a ValidationException ("...
    # not accessible ...") for a few seconds after the bucket/object are created,
    # even though both already exist. Poll until the source resolves.
    deadline = time.monotonic() + 60
    while True:
        try:
            good = os.create_package(
                PackageName=good_package_name,
                PackageType='TXT-DICTIONARY',
                PackageSource={'S3BucketName': bucket, 'S3Key': key},
            )['PackageDetails']
            break
        except ClientError as exc:
            code = exc.response.get('Error', {}).get('Code')
            msg = exc.response.get('Error', {}).get('Message', '')
            if code == 'ValidationException' and 'not accessible' in msg and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
    good_package_id = good['PackageID']

    def _cleanup_package(pid=good_package_id):
        try:
            os.delete_package(PackageID=pid)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_package)

    # ---- ListDomainsForPackage: a real package id succeeds (positive control) ...
    resp = os.list_domains_for_package(PackageID=good_package_id)
    assert resp.get('DomainPackageDetailsList', []) == [], (
        f'ListDomainsForPackage(valid id) should succeed with no associations, got {resp}'
    )
    # ... a malformed one is rejected.
    code, message = _error(lambda: os.list_domains_for_package(PackageID=malformed_package_id))
    assert code == 'ValidationException', f'ListDomainsForPackage(malformed id): got {code}'
    expected = _package_id_pattern_message(malformed_package_id)
    assert message == expected, f'ListDomainsForPackage(malformed id): expected {expected!r}, got {message!r}'

    # ---- CreatePackage: a real, accessible S3 source succeeds (the `good_package_id`
    # positive control above) ... a nonexistent one is rejected, never silently accepted.
    missing_bucket = ctx.unique_name('sim2real-behav-os-nobucket-src-')
    code, message = _error(lambda: os.create_package(
        PackageName=ctx.unique_name('sim2real-behav-pkg-bad-'),
        PackageType='TXT-DICTIONARY',
        PackageSource={'S3BucketName': missing_bucket, 'S3Key': 'nope.txt'},
    ))
    assert code == "ValidationException", (
        f'CreatePackage with a nonexistent S3 source should be rejected, got {code}'
    )
    expected = (
        'Package file not accessible. Please validate that you have access to the S3 object '
        'and S3 bucket is present in the same region.'
    )
    assert message == expected, f'CreatePackage(nonexistent S3 source): expected {expected!r}, got {message!r}'

    # ---- DeletePackage: a malformed id is rejected ...
    code, message = _error(lambda: os.delete_package(PackageID=malformed_package_id))
    assert code == 'ValidationException', f'DeletePackage(malformed id): got {code}'
    expected = _package_id_pattern_message(malformed_package_id)
    assert message == expected, f'DeletePackage(malformed id): expected {expected!r}, got {message!r}'
    # ... a real package id succeeds (positive control), and an independent read
    # confirms it is actually gone, not just that the call returned 200.
    os.delete_package(PackageID=good_package_id)
    deadline = time.monotonic() + 60
    remaining = None
    while time.monotonic() < deadline:
        remaining = os.describe_packages(
            Filters=[{'Name': 'PackageID', 'Value': [good_package_id]}]
        ).get('PackageDetailsList', [])
        if not remaining:
            break
        time.sleep(3)
    assert not remaining, f'DeletePackage(valid id) should remove it, still present: {remaining}'


def _package_id_pattern_message(sent: str) -> str:
    return (
        f"1 validation error detected: Value '{sent}' at 'packageID' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: ^([FG][0-9]+)$|^(pkg-[a-f0-9]+)$"
    )


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response['Error']['Code'], exc.response['Error'].get('Message')
    raise AssertionError(f'expected rejection, but the call SUCCEEDED and returned {result!r}')


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
