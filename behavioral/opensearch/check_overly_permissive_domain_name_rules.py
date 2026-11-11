"""overly-permissive-domain-name-rules."""
from __future__ import annotations
import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "overly-permissive-domain-name-rules"
GROUP = 'overly-permissive'
SERVICES = ['opensearch']
ENGINE_VERSION = 'OpenSearch_2.11'
MIN_CLUSTER_CONFIG = {'InstanceType': 't3.small.search', 'InstanceCount': 1}
MIN_EBS_OPTIONS = {'EBSEnabled': True, 'VolumeType': 'gp3', 'VolumeSize': 10}
_THROTTLE_CODES = ('ThrottlingException', 'TooManyRequestsException', 'RequestLimitExceeded')


def _delete_domain_quietly(osc, domain_name: str) -> None:
    """Idempotent teardown: tolerate a domain that was never created / already deleted. A name the
    service refuses to parse (ValidationException) names no domain, so there is nothing to delete."""
    try:
        osc.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') not in ('ResourceNotFoundException', 'ValidationException'):
            raise


def _account_access_policy(ctx, domain_name: str) -> str:
    account_id = ctx.account
    return json.dumps({
        'Version': '2012-10-17',
        'Statement': [{
            'Effect': 'Allow',
            'Principal': {'AWS': f"arn:aws:iam::{account_id}:root"},
            'Action': 'es:*',
            'Resource': f"arn:aws:es:{ctx.region}:{account_id}:domain/{domain_name}/*",
        }],
    })


def _create_domain_bounded(osc, domain_name: str, **overrides):
    """CreateDomain with the minimum legal topology; retries only on throttling, with a bounded
    deadline. CreateDomain is aggressively rate limited per account, so this is a real retry, not
    a decorative one."""
    kwargs = dict(
        DomainName=domain_name,
        EngineVersion=ENGINE_VERSION,
        ClusterConfig=dict(MIN_CLUSTER_CONFIG),
        EBSOptions=dict(MIN_EBS_OPTIONS),
    )
    kwargs.update(overrides)
    for attempt in range(10):
        try:
            return osc.create_domain(**kwargs)
        except ClientError as exc:
            if exc.response.get('Error', {}).get('Code') not in _THROTTLE_CODES:
                raise
            time.sleep(5.0 * (1 + attempt))
    raise AssertionError(f"CreateDomain({domain_name!r}) still throttled after 10 attempts")


def _expect_name_rejected(ctx, label: str, domain_name: str):
    """Attempt CreateDomain with a bad name; return (code, HTTP status, message). Registers cleanup up front
    so an unexpectedly-accepted create still gets torn down."""
    osc = ctx.client('opensearch')
    ctx.on_cleanup(lambda: _delete_domain_quietly(osc, domain_name))
    try:
        response = _create_domain_bounded(osc, domain_name)
    except ClientError as exc:
        code = exc.response.get('Error', {}).get('Code', '')
        message = exc.response.get('Error', {}).get('Message', '') or ''
        status = exc.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
        return code, status, message
    raise AssertionError(
        f"domain name violating {label!r} ({domain_name!r}) should have been rejected but "
        f"succeeded with DomainId={response['DomainStatus'].get('DomainId')}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDomain with an upper-case, digit-first or underscore name fails with ValidationException
    (400) and its exact message and leaves no domain, while a valid name is created and listed.
    """
    osc = ctx.client('opensearch')
    bad_names = {'uppercase letters': 'Sim2Real-Upper', 'leading digit': '9sim2real-digit', 'underscore': 'sim2real_under'}
    for label, name in bad_names.items():
        code, status, message = _expect_name_rejected(ctx, label, name)
        assert code == 'ValidationException' and status == 400, (
            f"domain name violating {label!r} ({name!r}) must be rejected with ValidationException/400, "
            f"got {code}/{status}: {message}"
        )
        expected_message = f"1 validation error detected: Value '{name}' at 'domainName' failed to satisfy constraint: Member must satisfy regular expression pattern: [a-z][a-z0-9\\-]+"
        assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"
        names = {d['DomainName'] for d in osc.list_domain_names()['DomainNames']}
        assert name not in names, (
            f"domain name violating {label!r} ({name!r}) was rejected but still appears in ListDomainNames"
        )

    # Positive control: a well-formed name is accepted and actually appears in ListDomainNames.
    valid_name = ctx.unique_name('sim2real-val-')[:28].rstrip('-') or 'sim2real-val-fallback'
    ctx.on_cleanup(lambda: _delete_domain_quietly(osc, valid_name))
    _create_domain_bounded(osc, valid_name, AccessPolicies=_account_access_policy(ctx, valid_name))
    names_after = {d['DomainName'] for d in osc.list_domain_names()['DomainNames']}
    assert valid_name in names_after, (
        f"a well-formed domain name {valid_name!r} was not accepted / did not appear in ListDomainNames"
    )
    # Independent read by name: the accepted domain is readable, not only listed.
    status = osc.describe_domain(DomainName=valid_name)['DomainStatus']
    assert status['DomainName'] == valid_name, (
        f"DescribeDomain({valid_name!r}) returned DomainName {status.get('DomainName')!r}"
    )


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
