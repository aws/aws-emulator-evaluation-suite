"""scheduled-action-and-maintenance-ops-on-missing-domain."""
from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "scheduled-action-and-maintenance-ops-on-missing-domain"
GROUP = 'domain'
SERVICES = ['opensearch']

def _missing_domain_name(ctx) -> str:
    """A syntactically valid domain name that is guaranteed not to exist."""
    return ctx.unique_name('sim2real-behav-os-missing-')[:28].rstrip('-')

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """For an unknown domain, ListScheduledActions fails with ResourceNotFoundException and
    ListDomainMaintenances with BaseException, both with "Domain not found: <name>".
    """
    os = ctx.client('opensearch')
    missing = _missing_domain_name(ctx)
    code, message = _error(lambda: os.list_scheduled_actions(DomainName=missing))
    assert code == 'ResourceNotFoundException', f'ListScheduledActions: got {code}'
    assert message == f'Domain not found: {missing}', f'ListScheduledActions: got message {message!r}'
    code, message = _error(lambda: os.list_domain_maintenances(DomainName=missing))
    assert code == 'BaseException', f'ListDomainMaintenances: expected BaseException, got {code}'
    assert message == f'Domain not found: {missing}', f'ListDomainMaintenances: got message {message!r}'


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
