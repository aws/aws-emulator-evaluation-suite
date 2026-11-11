"""get-compatible-versions-account-and-missing-domain."""
from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "get-compatible-versions-account-and-missing-domain"
GROUP = 'domain'
SERVICES = ['opensearch']

def _missing_domain_name(ctx) -> str:
    """A syntactically valid domain name that is guaranteed not to exist."""
    return ctx.unique_name('sim2real-behav-os-missing-')[:28].rstrip('-')

@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCompatibleVersions without a domain returns entries with SourceVersion and TargetVersions, and with
    an unknown domain fails with ResourceNotFoundException and its exact message.
    """
    os = ctx.client('opensearch')
    all_versions = os.get_compatible_versions().get('CompatibleVersions', [])
    assert len(all_versions) >= 1, 'account-wide GetCompatibleVersions returned no entries'
    assert all_versions[0].get('SourceVersion'), 'entry missing SourceVersion'
    assert all_versions[0].get('TargetVersions'), 'entry missing TargetVersions'
    missing = _missing_domain_name(ctx)
    code, message = _error(lambda: os.get_compatible_versions(DomainName=missing))
    assert code == 'ResourceNotFoundException', f'expected ResourceNotFoundException, got {code}'
    expected = f'Domain not found: {missing}'
    assert message == expected, f'expected message {expected!r}, got {message!r}'


def _error(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
