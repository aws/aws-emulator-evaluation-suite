"""instance-catalog-enum-semantics."""
from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "instance-catalog-enum-semantics"
GROUP = 'catalog'
SERVICES = ['opensearch']
ENGINE_VERSION = 'OpenSearch_2.11'

@tags("axis:happy-path", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListVersions offers an OpenSearch_ version, ListInstanceTypeDetails lists t3.small.search with LimitsByRole in
    DescribeInstanceTypeLimits, and DescribeInstanceTypeLimits for OpenSearch_99.99 fails with ValidationException
    "Unsupported Version: OpenSearch_99.99, allowed Versions are: [...]" listing OpenSearch_2.11.
    """
    os = ctx.client('opensearch')
    versions = os.list_versions().get('Versions', [])
    assert any((v.startswith('OpenSearch_') for v in versions)), f'ListVersions returned no OpenSearch_* versions: {versions[:5]}'
    details = os.list_instance_type_details(EngineVersion=ENGINE_VERSION).get('InstanceTypeDetails', [])
    assert details, 'ListInstanceTypeDetails returned nothing for a supported engine version'
    names = {d['InstanceType'] for d in details}
    assert 't3.small.search' in names, 'expected t3.small.search to be a supported instance type'
    limits = os.describe_instance_type_limits(InstanceType='t3.small.search', EngineVersion=ENGINE_VERSION)
    assert limits.get('LimitsByRole'), 'DescribeInstanceTypeLimits returned no LimitsByRole'
    try:
        os.describe_instance_type_limits(InstanceType='t3.small.search', EngineVersion='OpenSearch_99.99')
        code, message = None, None
    except ClientError as _e:
        code = _e.response.get('Error', {}).get('Code')
        message = _e.response.get('Error', {}).get('Message') or ''
    # message varies: it enumerates every engine version AWS currently offers, a list that grows
    # with each release, so the stable text before that list is asserted exactly.
    assert code == "ValidationException", f'bogus EngineVersion should be rejected, got {code}'
    prefix = 'Unsupported Version: OpenSearch_99.99, allowed Versions are: ['
    assert message.startswith(prefix) and message.endswith(']'), (
        f'expected the unsupported-version refusal {prefix!r}...], got {message!r}'
    )
    assert 'OpenSearch_2.11' in message[len(prefix):], (
        f'expected the allowed versions to list OpenSearch_2.11, got {message!r}'
    )
if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
