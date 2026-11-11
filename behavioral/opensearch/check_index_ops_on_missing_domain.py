"""index-ops-on-missing-domain."""
from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "index-ops-on-missing-domain"
GROUP = 'index'
SERVICES = ['opensearch']

def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'expected a rejection, but the call SUCCEEDED and returned {result!r}')

def _missing_domain_name(ctx) -> str:
    """A syntactically valid domain name that is guaranteed not to exist."""
    return ctx.unique_name('sim2real-behav-os-missing-')[:28].rstrip('-')

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """The index-management data-plane wrappers must resolve the domain first and
    reject an unknown DomainName with ResourceNotFoundException."""
    os = ctx.client('opensearch')
    missing = _missing_domain_name(ctx)
    index_name = ctx.unique_name('sim2real-behav-idx-')
    schema = {'settings': {'index': {'number_of_shards': 1, 'number_of_replicas': 0}}}
    expected = ('ResourceNotFoundException', f'Domain not found: {missing}')
    got = _error(lambda: os.create_index(DomainName=missing, IndexName=index_name, IndexSchema=schema))
    assert got == expected, f'CreateIndex: got {got}'
    got = _error(lambda: os.get_index(DomainName=missing, IndexName=index_name))
    assert got == expected, f'GetIndex: got {got}'
    got = _error(lambda: os.delete_index(DomainName=missing, IndexName=index_name))
    assert got == expected, f'DeleteIndex: got {got}'
    got = _error(lambda: os.update_index(DomainName=missing, IndexName=index_name, IndexSchema=schema))
    assert got == expected, f'UpdateIndex: got {got}'
if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
