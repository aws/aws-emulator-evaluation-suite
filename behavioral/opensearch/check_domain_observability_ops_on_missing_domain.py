"""domain-observability-ops-on-missing-domain."""
from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "domain-observability-ops-on-missing-domain"
GROUP = 'domain'
SERVICES = ['opensearch']

def _missing_domain_name(ctx) -> str:
    """A syntactically valid domain name that is guaranteed not to exist."""
    return ctx.unique_name('sim2real-behav-os-missing-')[:28].rstrip('-')

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeDomainHealth, DescribeDomainNodes and DescribeDomainChangeProgress for an unknown domain each
    fail with BaseException and its exact message, not ResourceNotFoundException.
    """
    os = ctx.client('opensearch')
    missing = _missing_domain_name(ctx)
    code, message = _error(lambda: os.describe_domain_health(DomainName=missing))
    assert code == 'BaseException', f'DescribeDomainHealth: expected BaseException, got {code}'
    expected = f'Domain not found: {missing}'
    assert message == expected, f'{code}: expected message {expected!r}, got {message!r}'
    code, message = _error(lambda: os.describe_domain_nodes(DomainName=missing))
    assert code == 'BaseException', f'DescribeDomainNodes: expected BaseException, got {code}'
    expected = f'Domain not found: {missing}'
    assert message == expected, f'{code}: expected message {expected!r}, got {message!r}'
    code, message = _error(lambda: os.describe_domain_change_progress(DomainName=missing))
    assert code == 'BaseException', f'DescribeDomainChangeProgress: expected BaseException, got {code}'
    expected = 'No progress information found'
    assert message == expected, f'{code}: expected message {expected!r}, got {message!r}'

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
