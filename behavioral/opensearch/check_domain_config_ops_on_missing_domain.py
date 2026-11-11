"""domain-config-ops-on-missing-domain."""
from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "domain-config-ops-on-missing-domain"
GROUP = 'domain'
SERVICES = ['opensearch']

def _missing_domain_name(ctx) -> str:
    """A syntactically valid domain name that is guaranteed not to exist."""
    return ctx.unique_name('sim2real-behav-os-missing-')[:28].rstrip('-')

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Every domain-scoped control-plane operation must reject an unknown
    DomainName with ResourceNotFoundException rather than inventing a resource."""
    os = ctx.client('opensearch')
    missing = _missing_domain_name(ctx)
    code, message = _error(lambda: os.describe_domain(DomainName=missing))
    assert code == 'ResourceNotFoundException', f'DescribeDomain: got {code}'
    expected = f'Domain not found: {missing}'
    assert message == expected, f'{code}: expected message {expected!r}, got {message!r}'
    code, message = _error(lambda: os.delete_domain(DomainName=missing))
    assert code == 'ResourceNotFoundException', f'DeleteDomain: got {code}'
    expected = f'Domain not found: {missing}'
    assert message == expected, f'{code}: expected message {expected!r}, got {message!r}'
    code, message = _error(lambda: os.describe_domain_config(DomainName=missing))
    assert code == 'ResourceNotFoundException', f'DescribeDomainConfig: got {code}'
    expected = f'Domain not found: {missing}'
    assert message == expected, f'{code}: expected message {expected!r}, got {message!r}'
    code, message = _error(lambda: os.update_domain_config(DomainName=missing, SnapshotOptions={'AutomatedSnapshotStartHour': 3}))
    assert code == 'ResourceNotFoundException', f'UpdateDomainConfig: got {code}'
    expected = f'Domain not found: {missing}'
    assert message == expected, f'{code}: expected message {expected!r}, got {message!r}'
    code, message = _error(lambda: os.cancel_domain_config_change(DomainName=missing, DryRun=True))
    assert code == 'ResourceNotFoundException', f'CancelDomainConfigChange: got {code}'
    expected = f'Domain not found: {missing}'
    assert message == expected, f'{code}: expected message {expected!r}, got {message!r}'
    names = {d['DomainName'] for d in os.list_domain_names()['DomainNames']}
    assert missing not in names, 'ListDomainNames returned a domain that was never created'

def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises: an
    emulator accepting a call real AWS refuses must not read as an ordinary code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'expected a rejection, but the call SUCCEEDED and returned {result!r}')


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
