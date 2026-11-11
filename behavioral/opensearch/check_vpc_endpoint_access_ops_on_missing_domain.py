"""vpc-endpoint-access-ops-on-missing-domain."""
from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "vpc-endpoint-access-ops-on-missing-domain"
GROUP = 'vpc-endpoint'
SERVICES = ['opensearch']

def _missing_domain_name(ctx) -> str:
    """A syntactically valid domain name that is guaranteed not to exist."""
    return ctx.unique_name('sim2real-behav-os-missing-')[:28].rstrip('-')

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """For an unknown domain, AuthorizeVpcEndpointAccess and RevokeVpcEndpointAccess fail with
    ResourceNotFoundException and their exact messages, while ListVpcEndpointAccess returns an empty
    AuthorizedPrincipalList.
    """
    os = ctx.client('opensearch')
    missing = _missing_domain_name(ctx)
    account_id = ctx.client('sts').get_caller_identity()['Account']
    expected = ("Either the domain doesn't exist, it doesn't support creation of VPC endpoints, "
                "or you don't have permission to create a VPC endpoint for the domain.")
    try:
        os.authorize_vpc_endpoint_access(DomainName=missing, Account=account_id)
        code, message = None, None
    except ClientError as _e:
        code, message = _e.response.get('Error', {}).get('Code'), _e.response.get('Error', {}).get('Message')
    assert code == 'ResourceNotFoundException', f'AuthorizeVpcEndpointAccess: expected ResourceNotFoundException, got {code}'
    assert message == expected, f'AuthorizeVpcEndpointAccess: expected message {expected!r}, got {message!r}'
    try:
        os.revoke_vpc_endpoint_access(DomainName=missing, Account=account_id)
        code, message = None, None
    except ClientError as _e:
        code, message = _e.response.get('Error', {}).get('Code'), _e.response.get('Error', {}).get('Message')
    assert code == 'ResourceNotFoundException', f'RevokeVpcEndpointAccess: expected ResourceNotFoundException, got {code}'
    assert message == expected, f'RevokeVpcEndpointAccess: expected message {expected!r}, got {message!r}'
    resp = os.list_vpc_endpoint_access(DomainName=missing)
    principals = resp['AuthorizedPrincipalList']
    assert principals == [], f"ListVpcEndpointAccess succeeds for an unknown domain but must return an empty AuthorizedPrincipalList, expected [], got {principals}"
if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
