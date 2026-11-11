"""data-source-ops-on-missing-domain."""
from __future__ import annotations
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "data-source-ops-on-missing-domain"
GROUP = 'data-source'
SERVICES = ['opensearch']

def _missing_domain_name(ctx) -> str:
    """A syntactically valid domain name that is guaranteed not to exist."""
    return ctx.unique_name('sim2real-behav-os-missing-')[:28].rstrip('-')

def _real_domain_name(ctx) -> str:
    return ctx.unique_name('sim2real-behav-os-real-')[:28].rstrip('-')

def _error(fn) -> "tuple[str, str]":
    """(code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response['Error']['Code'], exc.response['Error'].get('Message', '')
    raise AssertionError(f'real AWS rejects this call, but it SUCCEEDED and returned {result!r}')

def _create_domain(ctx, os, domain_name) -> None:
    os.create_domain(
        DomainName=domain_name,
        ClusterConfig={'InstanceType': 't3.small.search', 'InstanceCount': 1},
        EBSOptions={'EBSEnabled': True, 'VolumeType': 'gp3', 'VolumeSize': 10},
    )
    ctx.on_cleanup(lambda: os.delete_domain(DomainName=domain_name))

def _wait_domain_active(ctx, os, domain_name, timeout_s: float = 1450.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = os.describe_domain(DomainName=domain_name)['DomainStatus']
        if last.get('Processing') is False and last.get('Created') is True:
            return last
        time.sleep(2)
    raise AssertionError(f'domain {domain_name} never became Active within {timeout_s}s (last={last!r})')

def _list_data_sources_when_ready(os, domain_name, timeout_s: float = 300.0) -> dict:
    """A domain that just went Active can still answer data-source calls with
    DependencyFailureException ("The domain is not available now") for a short window;
    poll ListDataSources until that window closes."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return os.list_data_sources(DomainName=domain_name)
        except ClientError as exc:
            if exc.response['Error']['Code'] != 'DependencyFailureException':
                raise
            last = exc
        time.sleep(2)
    raise AssertionError(f'domain {domain_name} data-source API still unavailable after {timeout_s}s: {last!r}')

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """List/Get/DeleteDataSource on a missing domain are ResourceNotFoundException; on a real
    domain an unknown name is ValidationException for Get/Delete and an empty list for List,
    so domain resolution comes first and is distinct from the name-level failure.
    """
    os = ctx.client('opensearch')
    missing = _missing_domain_name(ctx)
    # The Name pattern is [a-z][a-z0-9_]+; a hyphen would draw ValidationException from the name.
    ds_name = ctx.unique_name('sim2real_behav_ds_').replace('-', '_')

    real_domain = _real_domain_name(ctx)
    _create_domain(ctx, os, real_domain)
    _wait_domain_active(ctx, os, real_domain)

    listed = _list_data_sources_when_ready(os, real_domain)
    assert listed.get('DataSources', []) == [], (
        f'ListDataSources on a real, empty domain: expected no data sources, got {listed}'
    )

    get_refusal = _error(lambda: os.get_data_source(DomainName=real_domain, Name=ds_name))
    delete_refusal = _error(lambda: os.delete_data_source(DomainName=real_domain, Name=ds_name))
    assert get_refusal == ('ValidationException', f"DataSource with name {ds_name} doesn't exist."), (
        f'GetDataSource on a real domain with an unknown name: expected ValidationException '
        f'with AWS exact message, got {get_refusal!r} (DeleteDataSource got {delete_refusal!r})'
    )
    assert delete_refusal == ('ValidationException', f"DataSource with name {ds_name} doesn't exist."), (
        f'DeleteDataSource on a real domain with an unknown name: expected ValidationException '
        f'with AWS exact message, got {delete_refusal!r}'
    )

    refusal = _error(lambda: os.list_data_sources(DomainName=missing))
    assert refusal == ('ResourceNotFoundException', f'Domain not found: {missing}'), (
        f'ListDataSources on a missing domain: got {refusal!r}'
    )

    refusal = _error(lambda: os.get_data_source(DomainName=missing, Name=ds_name))
    assert refusal == ('ResourceNotFoundException', f'Domain not found: {missing}'), (
        f'GetDataSource on a missing domain: got {refusal!r}'
    )

    refusal = _error(lambda: os.delete_data_source(DomainName=missing, Name=ds_name))
    assert refusal == ('ResourceNotFoundException', f'Domain not found: {missing}'), (
        f'DeleteDataSource on a missing domain: got {refusal!r}'
    )


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
