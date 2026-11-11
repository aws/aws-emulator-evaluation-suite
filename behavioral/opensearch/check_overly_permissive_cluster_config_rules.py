"""overly-permissive-cluster-config-rules."""
from __future__ import annotations
import random
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "overly-permissive-cluster-config-rules"
GROUP = 'overly-permissive'
SERVICES = ['opensearch']
MIN_EBS_OPTIONS = {'EBSEnabled': True, 'VolumeType': 'gp3', 'VolumeSize': 10}
ENGINE_VERSION = 'OpenSearch_2.11'

def _delete_domain_now(ctx, domain_name: str) -> None:
    """Best-effort immediate delete so checks do not leave 24x7 clusters running."""
    os = ctx.client('opensearch')
    try:
        os.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

def _create_or_throttle(os, name, cluster_config, ebs_options, tag_list):
    """CreateDomain with bounded backoff on throttling only; every other outcome
    (success or a real service error) returns immediately. Returns (code, message); both are
    None on success."""
    code, message = 'ThrottlingException', None
    for _attempt in range(10):
        try:
            os.create_domain(DomainName=name, EngineVersion=ENGINE_VERSION, ClusterConfig=cluster_config, EBSOptions=ebs_options, TagList=tag_list)
            code, message = None, None
        except ClientError as _e:
            code = _e.response.get('Error', {}).get('Code')
            message = _e.response.get('Error', {}).get('Message')
        if code not in ('ThrottlingException', 'TooManyRequestsException', 'RequestLimitExceeded'):
            break
        time.sleep(5.0 * (1 + _attempt) + random.uniform(0, 5.0))
    return code, message

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Overly-permissive detection: structurally invalid ClusterConfig combinations
    must be rejected at CreateDomain time, not silently normalized, while a
    structurally valid ClusterConfig in the same run is accepted (positive control)."""
    os = ctx.client('opensearch')
    tag_list = [{'Key': 'sim2real-check', 'Value': CHECK}]

    ctrl_name = ctx.unique_name('sim2real-behav-os-ctrl-')[:28].rstrip('-')
    ctx.on_cleanup(lambda n=ctrl_name: _delete_domain_now(ctx, n))
    code, _ = _create_or_throttle(os, ctrl_name, {'InstanceType': 't3.small.search', 'InstanceCount': 1}, dict(MIN_EBS_OPTIONS), tag_list)
    assert code is None, f'a structurally valid single-node domain must be accepted, got {code}'
    names_after_ctrl = {d['DomainName'] for d in os.list_domain_names()['DomainNames']}
    assert ctrl_name in names_after_ctrl, f'accepted control domain {ctrl_name} not visible via list_domain_names'

    za_name = ctx.unique_name('sim2real-behav-os-za-')[:28].rstrip('-')
    ctx.on_cleanup(lambda n=za_name: _delete_domain_now(ctx, n))
    code, message = _create_or_throttle(os, za_name, {'InstanceType': 't3.small.search', 'InstanceCount': 1, 'ZoneAwarenessEnabled': True, 'ZoneAwarenessConfig': {'AvailabilityZoneCount': 2}}, dict(MIN_EBS_OPTIONS), tag_list)
    assert code == 'ValidationException', f'zone awareness with a single data node must be rejected, got {code}'
    assert message == 'You must choose an even number of data nodes for a two Availability Zone deployment', f'unexpected refusal message for zone awareness with one data node: {message!r}'
    names_after_za = {d['DomainName'] for d in os.list_domain_names()['DomainNames']}
    assert za_name not in names_after_za, f'rejected domain {za_name} must not exist'

    zero_name = ctx.unique_name('sim2real-behav-os-zero-')[:28].rstrip('-')
    ctx.on_cleanup(lambda n=zero_name: _delete_domain_now(ctx, n))
    code, message = _create_or_throttle(os, zero_name, {'InstanceType': 't3.small.search', 'InstanceCount': 0}, dict(MIN_EBS_OPTIONS), tag_list)
    assert code == 'ValidationException', f'InstanceCount=0 must be rejected, got {code}'
    assert message == 'Instance Count should be greater than 0.', f'unexpected refusal message for InstanceCount=0: {message!r}'
    names_after_zero = {d['DomainName'] for d in os.list_domain_names()['DomainNames']}
    assert zero_name not in names_after_zero, f'rejected domain {zero_name} must not exist'
if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
