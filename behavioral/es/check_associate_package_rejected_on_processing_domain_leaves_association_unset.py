"""associate-package-rejected-on-processing-domain-leaves-association-unset."""
from __future__ import annotations

import random
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "associate-package-rejected-on-processing-domain-leaves-association-unset"
GROUP = 'packages'
SERVICES = ['es']

_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")


def _retry_throttled(fn, attempts: int = 8):
    """Call ``fn()``, retrying with backoff only on a throttle response."""
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES or attempt == attempts - 1:
                raise
            time.sleep(4.0 * (1 + attempt) + random.uniform(0, 3.0))


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociatePackage on a domain that is not yet on the latest service software is
    refused, and the rejected call leaves the package unassociated from both sides.
    """
    s3 = ctx.client("s3")
    es = ctx.client("es")
    bucket = ctx.unique_name("sim2real-behav-es-pkg-")
    s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_object(Bucket=bucket, Key="pkg.txt", Body=b"foo,bar\n")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key="pkg.txt"))

    package_name = ctx.unique_name("sim2realbehavpkg")[:28]
    pkg = es.create_package(
        PackageName=package_name, PackageType="TXT-DICTIONARY",
        PackageSource={"S3BucketName": bucket, "S3Key": "pkg.txt"},
    )["PackageDetails"]
    pkg_id = pkg["PackageID"]
    ctx.on_cleanup(lambda: es.delete_package(PackageID=pkg_id))

    domain_name = ctx.unique_name("sim2real-behav-es-")[:28].rstrip("-")
    _retry_throttled(lambda: es.create_elasticsearch_domain(
        DomainName=domain_name,
        ElasticsearchVersion="7.10",
        ElasticsearchClusterConfig={"InstanceType": "t3.small.elasticsearch", "InstanceCount": 1},
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp2", "VolumeSize": 10},
    ))
    ctx.on_cleanup(lambda: es.delete_elasticsearch_domain(DomainName=domain_name))

    code, message = _error(lambda: es.associate_package(PackageID=pkg_id, DomainName=domain_name))
    assert code == "ValidationException", (
        f"AssociatePackage on a Processing domain should be refused ValidationException, "
        f"got {code!r}: {message!r}"
    )
    assert message == (
        "The domain is not on the latest software version. "
        "Upgrade the domain to start using this feature. "
    ), f"unexpected message {message!r}"

    for_domain = es.list_packages_for_domain(DomainName=domain_name)["DomainPackageDetailsList"]
    assert for_domain == [], f"domain should list no associated packages, got {for_domain!r}"
    for_package = es.list_domains_for_package(PackageID=pkg_id)["DomainPackageDetailsList"]
    assert for_package == [], f"package should list no associated domains, got {for_package!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
