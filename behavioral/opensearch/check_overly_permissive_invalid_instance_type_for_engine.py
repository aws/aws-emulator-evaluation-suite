"""overly-permissive-invalid-instance-type-for-engine."""
from __future__ import annotations
import random
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "overly-permissive-invalid-instance-type-for-engine"
GROUP = 'overly-permissive'
SERVICES = ['opensearch']
MIN_EBS_OPTIONS = {'EBSEnabled': True, 'VolumeType': 'gp3', 'VolumeSize': 10}
ENGINE_VERSION = 'OpenSearch_2.11'

def _delete_domain_now(ctx, domain_name: str) -> None:
    """Immediate delete so checks do not leave 24x7 clusters running; only an absent domain is tolerated."""
    os = ctx.client('opensearch')
    try:
        os.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != 'ResourceNotFoundException':
            raise

def _create_control_domain(ctx) -> str:
    """Positive control: a supported instance type on the same engine version must be
    accepted, so the rejection below is known to target the instance type specifically
    and not everything CreateDomain is asked to do."""
    os = ctx.client('opensearch')
    name = ctx.unique_name('sim2real-behav-os-ctl-')[:28].rstrip('-')
    for _attempt in range(10):
        try:
            os.create_domain(DomainName=name, EngineVersion=ENGINE_VERSION, ClusterConfig={'InstanceType': 't3.small.search', 'InstanceCount': 1}, EBSOptions=dict(MIN_EBS_OPTIONS), TagList=[{'Key': 'sim2real', 'Value': 'overly-permissive-invalid-instance-type-for-engine'}])
            break
        except ClientError as _e:
            if _e.response.get('Error', {}).get('Code') not in ('ThrottlingException', 'TooManyRequestsException', 'RequestLimitExceeded'):
                raise
            time.sleep(5.0 * (1 + _attempt) + random.uniform(0, 5.0))
    else:
        raise AssertionError('still throttled after 10 attempts establishing the positive control')
    ctx.on_cleanup(lambda _n=name: _delete_domain_now(ctx, _n))
    return name

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDomain with instance type m1.xlarge.search fails with ValidationException whose enum-constraint
    message lists t3.small.search, and creates no domain, while a t3.small.search domain on the same engine
    version is created.
    """
    os = ctx.client('opensearch')
    _create_control_domain(ctx)
    domain_name = ctx.unique_name('sim2real-behav-os-it-')[:28].rstrip('-')
    try:
        for _attempt in range(10):
            try:
                os.create_domain(DomainName=domain_name, EngineVersion=ENGINE_VERSION, ClusterConfig={'InstanceType': 'm1.xlarge.search', 'InstanceCount': 1}, EBSOptions=dict(MIN_EBS_OPTIONS))
                code, message = None, None
            except ClientError as _e:
                code = _e.response.get('Error', {}).get('Code')
                message = _e.response.get('Error', {}).get('Message') or ''

            if code not in ('ThrottlingException', 'TooManyRequestsException', 'RequestLimitExceeded'):
                break
            time.sleep(5.0 * (1 + _attempt) + random.uniform(0, 5.0))
        else:
            code = 'ThrottlingException'
        assert code == "ValidationException", (
            f'an unsupported instance type must be rejected, got {code}'
        )
        # message varies: it embeds AWS's full instance-type enum in an unordered
        # form, and that set grows whenever a new instance family launches, so the stable
        # text before that set is asserted exactly.
        prefix = (
            "1 validation error detected: Value 'm1.xlarge.search' at 'clusterConfig.instanceType' "
            "failed to satisfy constraint: Member must satisfy enum value set: ["
        )
        assert message.startswith(prefix) and message.endswith(']'), (
            f'expected the enum-constraint refusal {prefix!r}...], got {message!r}'
        )
        assert 't3.small.search' in message[len(prefix):], (
            f'expected the enum value set to list t3.small.search, got {message!r}'
        )
        listed = [d['DomainName'] for d in os.list_domain_names()['DomainNames']]
        assert domain_name not in listed, f'a rejected CreateDomain must not create the domain, but {domain_name} appears in ListDomainNames'
    finally:
        _delete_domain_now(ctx, domain_name)
if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
