"""overly-permissive-access-policy-rejected."""
from __future__ import annotations
import json
import random
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "overly-permissive-access-policy-rejected"
GROUP = 'overly-permissive'
SERVICES = ['opensearch']
MIN_CLUSTER_CONFIG = {'InstanceType': 't3.small.search', 'InstanceCount': 1}
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

def _create_with_retry(os, name: str, access_policies: str, tag_list: list[dict]) -> tuple[str, str] | None:
    """Create a domain with the given AccessPolicies, retrying only on throttling.

    Every sleep -- the pre-call jitter that spreads concurrent CreateDomain calls apart
    (aggressively per-account rate limited) and the backoff on an observed throttle -- lives
    inside this loop, so the wait is bounded by the loop's own deadline rather than a bare sleep.
    Returns the ClientError (code, message), or None on success.
    """
    code = message = None
    for _attempt in range(10):
        time.sleep(random.uniform(0, 20.0) if _attempt == 0 else 5.0 * (1 + _attempt) + random.uniform(0, 5.0))
        try:
            os.create_domain(DomainName=name, EngineVersion=ENGINE_VERSION, ClusterConfig=dict(MIN_CLUSTER_CONFIG), EBSOptions=dict(MIN_EBS_OPTIONS), AccessPolicies=access_policies, TagList=tag_list)
            return None
        except ClientError as _e:
            code = _e.response.get('Error', {}).get('Code')
            message = _e.response.get('Error', {}).get('Message')
        if code not in ('ThrottlingException', 'TooManyRequestsException', 'RequestLimitExceeded'):
            return code, message
    return 'ThrottlingException', message

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A syntactically invalid AccessPolicies document is rejected with ValidationException rather than
    stored verbatim; a valid policy accepted first proves the rejection comes from validation."""
    os = ctx.client('opensearch')
    account_id = ctx.client('sts').get_caller_identity()['Account']
    tag_list = [{'Key': 'sim2real-check', 'Value': CHECK}]

    control_name = ctx.unique_name('sim2real-behav-os-ctl-')[:28].rstrip('-')
    ctx.on_cleanup(lambda: _delete_domain_now(ctx, control_name))
    valid_policy = json.dumps({
        'Version': '2012-10-17',
        'Statement': [{
            'Effect': 'Allow',
            'Principal': {'AWS': f'arn:aws:iam::{account_id}:root'},
            'Action': 'es:*',
            'Resource': f'arn:aws:es:{ctx.region}:{account_id}:domain/{control_name}/*',
        }],
    })
    control_code = _create_with_retry(os, control_name, valid_policy, tag_list)
    assert control_code is None, f'a syntactically valid AccessPolicies must be accepted (positive control), got {control_code}'

    name = ctx.unique_name('sim2real-behav-os-pol-')[:28].rstrip('-')
    rejected = _create_with_retry(os, name, 'this-is-not-json', tag_list)
    if rejected is None:
        _delete_domain_now(ctx, name)
    code, message = rejected or (None, None)
    assert code == 'ValidationException', f'a non-JSON AccessPolicies document must be rejected, got {code}'
    assert message == 'This policy contains invalid Json', f'unexpected refusal message for a non-JSON AccessPolicies document: {message!r}'

    domains = {d['DomainName'] for d in os.list_domain_names().get('DomainNames', [])}
    assert name not in domains, f'rejected domain {name!r} must never exist, but ListDomainNames shows {sorted(domains)}'
if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
