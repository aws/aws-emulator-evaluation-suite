"""describe-security-policy-not-found."""
from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "describe-security-policy-not-found"
GROUP = 'error-semantics'
SERVICES = ['transfer']

@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeSecurityPolicy resolves a policy name that ListSecurityPolicies returns, and fails with
    ResourceNotFoundException "Unknown SecurityPolicy" for an unknown name."""
    tf = ctx.client('transfer')

    real_names = tf.list_security_policies().get('SecurityPolicyNames', [])
    assert real_names, 'ListSecurityPolicies returned no built-in policies'
    real_name = real_names[0]
    resolved = tf.describe_security_policy(SecurityPolicyName=real_name)['SecurityPolicy']
    assert resolved['SecurityPolicyName'] == real_name, (
        f"positive control: expected DescribeSecurityPolicy({real_name!r}) to resolve "
        f"that name, got {resolved!r}"
    )

    try:
        tf.describe_security_policy(SecurityPolicyName='TransferSecurityPolicy-does-not-exist-9999-99')
    except ClientError as _e:
        code = _e.response.get('Error', {}).get('Code')
        message = _e.response.get('Error', {}).get('Message')
    else:
        raise AssertionError("expected an unknown policy name to be rejected, but the call succeeded")
    assert code == 'ResourceNotFoundException', (
        f"expected ResourceNotFoundException for an unknown policy name, got {code!r}"
    )
    assert message == 'Unknown SecurityPolicy', f"unexpected not-found message: {message!r}"
if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
