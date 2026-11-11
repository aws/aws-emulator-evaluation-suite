"""overly-permissive-engine-version-rejected."""
from __future__ import annotations
import random
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "overly-permissive-engine-version-rejected"
GROUP = 'overly-permissive'
SERVICES = ['opensearch']
MIN_CLUSTER_CONFIG = {'InstanceType': 't3.small.search', 'InstanceCount': 1}
MIN_EBS_OPTIONS = {'EBSEnabled': True, 'VolumeType': 'gp3', 'VolumeSize': 10}

def _delete_domain_now(ctx, domain_name: str) -> None:
    """Immediate delete so checks do not leave 24x7 clusters running; only an absent domain is tolerated."""
    os = ctx.client('opensearch')
    try:
        os.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != 'ResourceNotFoundException':
            raise

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDomain with EngineVersion OpenSearch_99.99 fails with ValidationException "Unsupported Version:
    OpenSearch_99.99, allowed Versions are: [...]" listing OpenSearch_2.11 and creates no domain, while an
    OpenSearch_2.11 CreateDomain succeeds and appears in ListDomainNames.
    """
    os = ctx.client('opensearch')
    for bad_version in ('OpenSearch_99.99',):
        name = ctx.unique_name('sim2real-behav-os-ev-')[:28].rstrip('-')
        ctx.on_cleanup(lambda n=name: _delete_domain_now(ctx, n))
        time.sleep(random.uniform(0, 20.0))
        for _attempt in range(10):
            try:
                os.create_domain(DomainName=name, EngineVersion=bad_version, ClusterConfig=dict(MIN_CLUSTER_CONFIG), EBSOptions=dict(MIN_EBS_OPTIONS))
                code, message = None, None
            except ClientError as _e:
                code = _e.response.get('Error', {}).get('Code')
                message = _e.response.get('Error', {}).get('Message') or ''
            if code not in ('ThrottlingException', 'TooManyRequestsException', 'RequestLimitExceeded'):
                break
            time.sleep(5.0 * (1 + _attempt) + random.uniform(0, 5.0))
        else:
            code = 'ThrottlingException'
        if code is None:
            _delete_domain_now(ctx, name)
        assert code == "ValidationException", (
            f'EngineVersion {bad_version!r} must be rejected, got {code}'
        )
        # message varies: it lists every currently allowed engine version, which grows with each
        # release, so the stable text before that list is asserted exactly.
        prefix = f'Unsupported Version: {bad_version}, allowed Versions are: ['
        assert message.startswith(prefix) and message.endswith(']'), (
            f'expected the unsupported-version refusal {prefix!r}...], got {message!r}'
        )
        assert 'OpenSearch_2.11' in message[len(prefix):], (
            f'expected the allowed versions to list OpenSearch_2.11, got {message!r}'
        )
        names = {d['DomainName'] for d in os.list_domain_names()['DomainNames']}
        assert name not in names, f'rejected EngineVersion {bad_version!r} unexpectedly created domain {name!r}, found in ListDomainNames: {sorted(names)!r}'

    valid_name = ctx.unique_name('sim2real-behav-os-evok-')[:28].rstrip('-')
    ctx.on_cleanup(lambda: _delete_domain_now(ctx, valid_name))
    for _attempt in range(10):
        try:
            os.create_domain(DomainName=valid_name, EngineVersion='OpenSearch_2.11', ClusterConfig=dict(MIN_CLUSTER_CONFIG), EBSOptions=dict(MIN_EBS_OPTIONS))
            control_code = None
        except ClientError as _e:
            control_code = _e.response.get('Error', {}).get('Code')
        if control_code not in ('ThrottlingException', 'TooManyRequestsException', 'RequestLimitExceeded'):
            break
        time.sleep(5.0 * (1 + _attempt) + random.uniform(0, 5.0))
    else:
        control_code = 'ThrottlingException'
    assert control_code is None, f'positive control: create_domain with a valid EngineVersion must succeed, got {control_code}'
    names_after = {d['DomainName'] for d in os.list_domain_names()['DomainNames']}
    assert valid_name in names_after, f'positive-control domain {valid_name!r} missing from ListDomainNames: {sorted(names_after)!r}'
if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
