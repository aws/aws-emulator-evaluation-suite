"""package-association-ops-on-missing-domain."""
from __future__ import annotations
import uuid
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "package-association-ops-on-missing-domain"
GROUP = 'package'
SERVICES = ['opensearch']

def _missing_domain_name(ctx) -> str:
    """A syntactically valid domain name that is guaranteed not to exist."""
    return ctx.unique_name('sim2real-behav-os-missing-')[:28].rstrip('-')

def _missing_package_id() -> str:
    """A PackageID that matches the service's own pattern (``^([FG][0-9]+)$|^(pkg-[a-f0-9]+)$``) but
    was never created. A malformed id (e.g. ``not-a-package-id``) would be rejected by format
    validation alone so it cannot exercise the missing-domain path this check exists to test."""
    return f'pkg-{uuid.uuid4().hex[:16]}'

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """For an unknown domain, ListPackagesForDomain returns an empty list, while AssociatePackage and
    DissociatePackage with a well-formed unknown package id fail with ValidationException and their exact
    messages and leave no association.
    """
    os = ctx.client('opensearch')
    missing_domain = _missing_domain_name(ctx)
    missing_package_id = _missing_package_id()
    resp = os.list_packages_for_domain(DomainName=missing_domain)
    assert resp.get('DomainPackageDetailsList', []) == [], f"ListPackagesForDomain succeeds for an unknown domain but must return an empty list, got {resp.get('DomainPackageDetailsList')}"
    resp = os.describe_packages(Filters=[{'Name': 'PackageName', 'Value': [ctx.unique_name('sim2real-behav-pkg-none-')]}])
    assert resp.get('PackageDetailsList', []) == [], 'DescribePackages must return an empty list for a non-matching filter'
    code, message = _error(lambda: os.associate_package(PackageID=missing_package_id, DomainName=missing_domain))
    assert code == 'ValidationException', f'AssociatePackage(unknown domain, well-formed but nonexistent package id): got {code}'
    expected = f'The domain {missing_domain} does not exist.'
    assert message == expected, f'AssociatePackage(unknown domain): expected message {expected!r}, got {message!r}'
    code, message = _error(lambda: os.dissociate_package(PackageID=missing_package_id, DomainName=missing_domain))
    assert code == 'ValidationException', f'DissociatePackage(unknown domain, well-formed but nonexistent package id): got {code}'
    expected = 'The domain is not on the latest software version. Upgrade the domain to start using this feature. '
    assert message == expected, f'DissociatePackage(unknown domain): expected message {expected!r}, got {message!r}'
    resp = os.list_packages_for_domain(DomainName=missing_domain)
    assert resp.get('DomainPackageDetailsList', []) == [], f"the rejected AssociatePackage/DissociatePackage calls must leave no association, got {resp.get('DomainPackageDetailsList')}"


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
