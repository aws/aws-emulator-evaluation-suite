"""service-software-ops-on-missing-domain."""
from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "service-software-ops-on-missing-domain"
GROUP = 'domain'
SERVICES = ['opensearch']

def _missing_domain_name(ctx) -> str:
    """A syntactically valid domain name that is guaranteed not to exist."""
    return ctx.unique_name('sim2real-behav-os-missing-')[:28].rstrip('-')

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Service-software and upgrade operations must reject an unknown domain with
    ResourceNotFoundException instead of reporting a fabricated update state."""
    os = ctx.client('opensearch')
    missing = _missing_domain_name(ctx)
    code, message = _error(lambda: os.start_service_software_update(DomainName=missing))
    assert code == 'ResourceNotFoundException', f'StartServiceSoftwareUpdate: got {code}'
    assert message == f'Domain not found: {missing}', f'StartServiceSoftwareUpdate: got message {message!r}'
    code, message = _error(lambda: os.cancel_service_software_update(DomainName=missing))
    assert code == 'ResourceNotFoundException', f'CancelServiceSoftwareUpdate: got {code}'
    assert message == f'Domain not found: {missing}', f'CancelServiceSoftwareUpdate: got message {message!r}'
    code, message = _error(lambda: os.get_upgrade_status(DomainName=missing))
    assert code == 'ResourceNotFoundException', f'GetUpgradeStatus: got {code}'
    assert message == f'Domain not found: {missing}', f'GetUpgradeStatus: got message {message!r}'
    code, message = _error(lambda: os.get_upgrade_history(DomainName=missing))
    assert code == 'ResourceNotFoundException', f'GetUpgradeHistory: got {code}'
    assert message == f'Domain not found: {missing}', f'GetUpgradeHistory: got message {message!r}'

def _error(fn) -> tuple:
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as _e:
        error = _e.response.get('Error', {})
        return error.get('Code'), error.get('Message')
    raise AssertionError(f'a missing domain must be rejected, but the call SUCCEEDED and returned {result!r}')


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
