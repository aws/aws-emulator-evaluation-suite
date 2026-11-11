"""domain-lifecycle-create-active-delete."""
from __future__ import annotations
import random
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "domain-lifecycle-create-active-delete"
GROUP = 'domain'
SERVICES = ['opensearch']
MIN_CLUSTER_CONFIG = {'InstanceType': 't3.small.search', 'InstanceCount': 1}
MIN_EBS_OPTIONS = {'EBSEnabled': True, 'VolumeType': 'gp3', 'VolumeSize': 10}
ENGINE_VERSION = 'OpenSearch_2.11'

def _create_test_domain(ctx, engine_version: str=ENGINE_VERSION) -> tuple[str, dict]:
    """Create a minimal domain and return its name and CreateDomain DomainStatus, without waiting for Active.

    Provisioning takes 15-30 minutes, longer than the check's time budget.
    """
    os = ctx.client('opensearch')
    domain_name = ctx.unique_name('sim2real-behav-os-')[:28].rstrip('-')
    for _attempt in range(12):
        try:
            _res = os.create_domain(DomainName=domain_name, EngineVersion=engine_version, ClusterConfig=dict(MIN_CLUSTER_CONFIG), EBSOptions=dict(MIN_EBS_OPTIONS))
            break
        except ClientError as _e:
            if _e.response.get('Error', {}).get('Code') not in ('ThrottlingException', 'TooManyRequestsException', 'RequestLimitExceeded'):
                raise
            time.sleep(6.0 * (1 + _attempt) + random.uniform(0, 6.0))
    else:
        raise AssertionError('still throttled after 12 attempts')
    ctx.on_cleanup(lambda _k=domain_name: _delete_domain(os, _k))
    return domain_name, _res['DomainStatus']

def _delete_domain(os, domain_name: str) -> None:
    """DeleteDomain; a domain the check already deleted may be gone."""
    try:
        os.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response['Error']['Code'] != 'ResourceNotFoundException':
            raise

def _missing_domain_name(ctx) -> str:
    """A syntactically valid domain name that is guaranteed not to exist."""
    return ctx.unique_name('sim2real-behav-os-missing-')[:28].rstrip('-')

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Creating domain echoes its config, repeat create is idempotent, list/describe/tags/versions
    agree, and DeleteDomain leaves it Deleted=True and Processing=True.
    """
    os = ctx.client('opensearch')
    # One domain serves every contract: CreateDomain is rate limited hard.
    domain_name, create_status = _create_test_domain(ctx)
    # Processing and Endpoint come from the CreateDomain answer itself: a later read races the
    # domain's provisioning.
    assert create_status.get('Processing') is True, 'a freshly created domain must report Processing=True'
    assert not create_status.get('Endpoint'), 'Endpoint must not be published while still Creating'
    created = os.describe_domain(DomainName=domain_name)['DomainStatus']
    assert created['DomainName'] == domain_name, f"DescribeDomain returned the wrong DomainName: {created['DomainName']!r}"
    assert created['Created'] is True, f"a freshly created domain must report Created=True, got {created['Created']!r}"
    assert created['Deleted'] is False, f"a freshly created domain must report Deleted=False, got {created['Deleted']!r}"
    assert created['ClusterConfig']['InstanceType'] == 't3.small.search', f"ClusterConfig.InstanceType did not echo the request: {created['ClusterConfig']['InstanceType']!r}"
    assert created['ClusterConfig']['InstanceCount'] == 1, f"ClusterConfig.InstanceCount did not echo the request: {created['ClusterConfig']['InstanceCount']!r}"
    assert created['EBSOptions']['EBSEnabled'] is True, f"EBSOptions.EBSEnabled did not echo the request: {created['EBSOptions']['EBSEnabled']!r}"
    assert created['EngineVersion'] == ENGINE_VERSION, f"EngineVersion did not echo the request: {created['EngineVersion']!r} != {ENGINE_VERSION!r}"
    arn = created['ARN']
    assert arn.endswith(f':domain/{domain_name}'), f'ARN {arn!r} does not end with the expected domain/{domain_name} suffix'
    cfg = os.describe_domain_config(DomainName=domain_name)['DomainConfig']
    assert cfg['ClusterConfig']['Options']['InstanceCount'] == 1, f"DescribeDomainConfig.ClusterConfig.InstanceCount did not echo the request: {cfg['ClusterConfig']['Options']['InstanceCount']!r}"
    assert cfg['EBSOptions']['Options']['VolumeSize'] == 10, f"DescribeDomainConfig.EBSOptions.VolumeSize did not echo the request: {cfg['EBSOptions']['Options']['VolumeSize']!r}"
    assert cfg['ClusterConfig']['Status']['State'] in ('Processing', 'Active', 'RequiresIndexDocuments'), f"unexpected ClusterConfig.Status.State: {cfg['ClusterConfig']['Status']['State']!r}"
    assert isinstance(cfg['ClusterConfig']['Status']['UpdateVersion'], int), f"ClusterConfig.Status.UpdateVersion must be an int, got {cfg['ClusterConfig']['Status']['UpdateVersion']!r}"
    for _attempt in range(12):
        try:
            dup_resp = os.create_domain(DomainName=domain_name, EngineVersion=ENGINE_VERSION, ClusterConfig=dict(MIN_CLUSTER_CONFIG), EBSOptions=dict(MIN_EBS_OPTIONS))
            break
        except ClientError as _e:
            if _e.response.get('Error', {}).get('Code') not in ('ThrottlingException', 'TooManyRequestsException', 'RequestLimitExceeded'):
                raise
            time.sleep(6.0 * (1 + _attempt) + random.uniform(0, 6.0))
    else:
        raise AssertionError('still throttled after 12 attempts')
    assert dup_resp['DomainStatus']['DomainName'] == domain_name, 'an idempotent repeat create must resolve to the same domain'
    same_name = [d for d in os.list_domain_names()['DomainNames'] if d['DomainName'] == domain_name]
    assert len(same_name) == 1, f'an idempotent repeat create must not fork the resource: found {len(same_name)} domains named {domain_name}'
    entries = {d['DomainName']: d for d in os.list_domain_names()['DomainNames']}
    assert domain_name in entries, 'ListDomainNames omitted a freshly created domain'
    assert entries[domain_name].get('EngineType') == 'OpenSearch', f"ListDomainNames reported the wrong EngineType: {entries[domain_name].get('EngineType')!r}"
    es_names = {d['DomainName'] for d in os.list_domain_names(EngineType='Elasticsearch')['DomainNames']}
    assert domain_name not in es_names, 'EngineType filter leaked an OpenSearch domain'
    batch = os.describe_domains(DomainNames=[domain_name, _missing_domain_name(ctx)])
    batch_names = {d['DomainName'] for d in batch['DomainStatusList']}
    assert batch_names == {domain_name}, f'DescribeDomains must return only the existing domain, got {batch_names}'
    compat = os.get_compatible_versions(DomainName=domain_name).get('CompatibleVersions', [])
    assert len(compat) >= 1, 'expected a CompatibleVersions entry for an existing domain'
    assert compat[0]['SourceVersion'] == ENGINE_VERSION, f"CompatibleVersions[0].SourceVersion did not match the created engine version: {compat[0]['SourceVersion']!r} != {ENGINE_VERSION!r}"
    assert compat[0].get('TargetVersions'), 'expected non-empty TargetVersions'
    os.add_tags(ARN=arn, TagList=[{'Key': 'env', 'Value': 'test'}, {'Key': 'team', 'Value': 'fidelity'}])
    tags = {t['Key']: t['Value'] for t in os.list_tags(ARN=arn)['TagList']}
    assert tags.get('env') == 'test', f"ListTags after AddTags did not reflect env=test, got {tags.get('env')!r}"
    assert tags.get('team') == 'fidelity', f"ListTags after AddTags did not reflect team=fidelity, got {tags.get('team')!r}"
    os.remove_tags(ARN=arn, TagKeys=['team'])
    tags_after = {t['Key']: t['Value'] for t in os.list_tags(ARN=arn)['TagList']}
    assert 'team' not in tags_after, 'RemoveTags did not remove the tag'
    assert tags_after.get('env') == 'test', 'RemoveTags removed an unrelated tag'
    os.add_tags(ARN=arn, TagList=[{'Key': 'env', 'Value': 'prod'}])
    env_entries = [t for t in os.list_tags(ARN=arn)['TagList'] if t['Key'] == 'env']
    assert len(env_entries) == 1, f"expected one 'env' tag, got {env_entries}"
    assert env_entries[0]['Value'] == 'prod', f"AddTags did not overwrite the existing env tag's value: {env_entries[0]['Value']!r}"
    delete_resp = os.delete_domain(DomainName=domain_name)
    assert delete_resp['DomainStatus']['Deleted'] is True, 'DeleteDomain must flip Deleted=True'
    assert delete_resp['DomainStatus']['DomainName'] == domain_name, f"DeleteDomain response did not echo the domain name: {delete_resp['DomainStatus']['DomainName']!r}"
    assert delete_resp['DomainStatus']['Processing'] is True, 'a deleting domain must still be Processing'
    # Deletion converges past the time budget: a follow-up read sees the domain Deleting or already gone.
    try:
        deleting = os.describe_domain(DomainName=domain_name)['DomainStatus']
    except ClientError as exc:
        assert exc.response['Error']['Code'] == 'ResourceNotFoundException', f"DescribeDomain after DeleteDomain failed with {exc.response['Error']['Code']!r}"
        assert exc.response['Error'].get('Message') == f'Domain not found: {domain_name}', f"DescribeDomain after DeleteDomain: unexpected message {exc.response['Error'].get('Message')!r}"
    else:
        assert deleting['Deleted'] is True, 'a deleting domain must keep reporting Deleted=True'
if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
