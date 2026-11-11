"""list-dedicated-ip-pools-forged-next-token-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-dedicated-ip-pools-forged-next-token-rejected"
GROUP = 'dedicated-ip-pool-paging'
SERVICES = ['sesv2']

_FORGED_TOKEN = 'c2ltMnJlYWwtZm9yZ2VkLW5leHQtdG9rZW4='


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListDedicatedIpPools refuses a forged NextToken with BadRequestException instead of serving
    page one; a real pool is still listed when called without the token."""
    sesv2 = ctx.client('sesv2')
    pool = ctx.unique_name('sim2real-behav-dip-')
    sesv2.create_dedicated_ip_pool(PoolName=pool, ScalingMode='STANDARD')
    ctx.on_cleanup(lambda: sesv2.delete_dedicated_ip_pool(PoolName=pool))

    try:
        resp = sesv2.list_dedicated_ip_pools(PageSize=1, NextToken=_FORGED_TOKEN)
    except ClientError as exc:
        code = exc.response['Error']['Code']
        msg = exc.response['Error'].get('Message')
        assert code == 'BadRequestException', (
            f"a forged NextToken must be refused with BadRequestException, got {code!r}: {msg!r}"
        )
        expected_msg = "Invalid next token."
        assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"
    else:
        raise AssertionError(
            'a forged NextToken was silently accepted and served as a page -- an opaque cursor '
            f"that is never validated lets a caller silently restart the list: got "
            f"{resp.get('DedicatedIpPools')!r} and NextToken={resp.get('NextToken')!r}"
        )

    # Positive control: the pool itself is listed when called without a forged token.
    found = pool in sesv2.list_dedicated_ip_pools().get('DedicatedIpPools', [])
    assert found, f"expected {pool!r} in ListDedicatedIpPools, got none matching"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
