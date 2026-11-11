"""vpc-endpoint-error-semantics."""
from __future__ import annotations
import random
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "vpc-endpoint-error-semantics"
GROUP = 'vpc-endpoint'
SERVICES = ['opensearch']

def _missing_domain_name(ctx) -> str:
    """A syntactically valid domain name that is guaranteed not to exist."""
    return ctx.unique_name('sim2real-behav-os-missing-')[:28].rstrip('-')

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """VPC endpoint APIs: unknown domain ARNs are rejected, unknown endpoint ids
    are reported via the VpcEndpointErrors channel on describe (not an exception)
    but as ResourceNotFoundException on mutation."""
    os = ctx.client('opensearch')
    subnet_id = _create_subnet(ctx)
    bogus_domain_arn = f"arn:aws:es:{ctx.region}:{ctx.client('sts').get_caller_identity()['Account']}:domain/{_missing_domain_name(ctx)}"
    bogus_endpoint_id = 'aos-' + ctx.unique_name('sim2real-behav-').replace('-', '')[:17]
    # A subnet the check created, so the rejection is about the domain: AWS validates the
    # subnet ids before the domain and names a nonexistent subnet instead.
    code, message = _error_detail(lambda: os.create_vpc_endpoint(DomainArn=bogus_domain_arn, VpcOptions={'SubnetIds': [subnet_id]}))
    assert code == 'ValidationException', f'CreateVpcEndpoint with an unknown domain should be rejected with ValidationException, got {code}'
    expected = "Either the domain doesn't exist, it doesn't support creation of VPC endpoints, or you don't have permission to create a VPC endpoint for the domain."
    assert message == expected, f'expected message {expected!r}, got {message!r}'
    resp = os.describe_vpc_endpoints(VpcEndpointIds=[bogus_endpoint_id])
    assert resp.get('VpcEndpoints', []) == [], 'DescribeVpcEndpoints fabricated an endpoint'
    errors = resp.get('VpcEndpointErrors', [])
    assert len(errors) == 1, f'expected one VpcEndpointError entry, got {errors}'
    assert errors[0]['ErrorCode'] == 'ENDPOINT_NOT_FOUND', f"expected ENDPOINT_NOT_FOUND, got {errors[0]['ErrorCode']!r}"
    assert errors[0].get('ErrorMessage') == 'Endpoint does not exist', f"expected ErrorMessage 'Endpoint does not exist', got {errors[0].get('ErrorMessage')!r}"
    code, message = _error_detail(lambda: os.delete_vpc_endpoint(VpcEndpointId=bogus_endpoint_id))
    assert code == 'ResourceNotFoundException', f'DeleteVpcEndpoint on an unknown endpoint id should be rejected with ResourceNotFoundException, got {code}'
    expected = "The VPC endpoint doesn't exist, or you don't have access to it."
    assert message == expected, f'expected message {expected!r}, got {message!r}'
    for _attempt in range(12):
        try:
            listing = os.list_vpc_endpoints()
            break
        except ClientError as _e:
            if _e.response.get('Error', {}).get('Code') not in ('ThrottlingException', 'TooManyRequestsException', 'RequestLimitExceeded'):
                raise
            time.sleep(6.0 * (1 + _attempt) + random.uniform(0, 6.0))
    else:
        raise AssertionError('still throttled after 12 attempts')
    ids = {e['VpcEndpointId'] for e in listing.get('VpcEndpointSummaryList', [])}
    assert bogus_endpoint_id not in ids, f'ListVpcEndpoints fabricated {bogus_endpoint_id} in {ids}'

def _error_detail(fn):
    """(code, message) of the ClientError fn raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response['Error']['Code'], exc.response['Error'].get('Message')
    raise AssertionError(f'expected a rejection, but the call SUCCEEDED and returned {result!r}')


def _create_subnet(ctx) -> str:
    """A subnet in a VPC this check creates, both removed at cleanup."""
    ec2 = ctx.client('ec2')
    tags = [{'Key': 'sim2real', 'Value': CHECK}]
    vpc_id = ec2.create_vpc(CidrBlock='10.91.0.0/16', TagSpecifications=[{'ResourceType': 'vpc', 'Tags': tags}])['Vpc']['VpcId']
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    zone = ec2.describe_availability_zones(Filters=[{'Name': 'state', 'Values': ['available']}])['AvailabilityZones'][0]['ZoneName']
    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock='10.91.1.0/24', AvailabilityZone=zone, TagSpecifications=[{'ResourceType': 'subnet', 'Tags': tags}])['Subnet']['SubnetId']
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    return subnet_id


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
