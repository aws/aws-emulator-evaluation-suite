"""dedicated-ip-pool-lifecycle."""
from __future__ import annotations
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "dedicated-ip-pool-lifecycle"
GROUP = 'dedicated-ip-pool'
SERVICES = ['sesv2']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """create -> get -> list(contains) -> delete -> get(NotFound) -> mutate(BadRequest|NotFound)."""
    ses = ctx.client('sesv2')
    pool_name = ctx.unique_name('sim2real-behav-pool-')
    ses.create_dedicated_ip_pool(PoolName=pool_name, ScalingMode='STANDARD', Tags=[{'Key': 'sim2real:managed', 'Value': 'true'}])
    ctx.on_cleanup(lambda _k=pool_name: _tolerate_missing(lambda: ses.delete_dedicated_ip_pool(PoolName=_k)))
    got = ses.get_dedicated_ip_pool(PoolName=pool_name)
    assert got['DedicatedIpPool']['PoolName'] == pool_name, f"expected PoolName {pool_name!r}, got {got['DedicatedIpPool'].get('PoolName')!r}"

    _deadline = time.monotonic() + 30
    present = False
    while time.monotonic() < _deadline:
        present = pool_name in ses.list_dedicated_ip_pools().get('DedicatedIpPools', [])
        if present:
            break
        time.sleep(2.0)
    assert present, f'{pool_name!r} not present in ListDedicatedIpPools within 30s'

    ses.delete_dedicated_ip_pool(PoolName=pool_name)
    err = _error(lambda: ses.get_dedicated_ip_pool(PoolName=pool_name))
    expected = ('NotFoundException', f'The requested pool <{pool_name}> does not exist.')
    assert err == expected, f'expected {expected}, got {err}'

    # PutDedicatedIpPoolScalingAttributes on a pool that no longer exists rejects with
    # BadRequestException ("The ScalingMode parameter is invalid."), not the NotFoundException
    # GetDedicatedIpPool/DeleteDedicatedIpPool give for the same dead id: NotFoundException is a
    # declared error for this operation too, but SES rejects the mutation before it resolves the
    # pool. No validation order is
    # documented, so resolving the pool first (the same NotFoundException as above) passes too.
    mutate_err = _error(lambda: ses.put_dedicated_ip_pool_scaling_attributes(PoolName=pool_name, ScalingMode='STANDARD'))
    expected_mutate = ('BadRequestException', 'The ScalingMode parameter is invalid.')
    assert mutate_err == expected_mutate or mutate_err == expected, (
        f'expected a mutation on the deleted pool to be rejected with {expected_mutate} or '
        f'{expected}, got {mutate_err!r}'
    )


def _error(fn):
    """Return the (code, message) of the ClientError fn raises; raise if fn succeeds."""
    try:
        result = fn()
    except ClientError as _e:
        _err = _e.response.get('Error', {})
        return (_err.get('Code'), _err.get('Message'))
    raise AssertionError(f'expected a ClientError, the call succeeded with {result!r}')


def _tolerate_missing(fn):
    """Teardown: run fn, treating NotFoundException as already gone."""
    try:
        fn()
    except ClientError as _e:
        if _e.response.get('Error', {}).get('Code') != 'NotFoundException':
            raise


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
