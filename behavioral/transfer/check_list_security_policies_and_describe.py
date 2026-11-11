"""list-security-policies-and-describe."""
from __future__ import annotations

from behavioral_harness import tags
CHECK = "list-security-policies-and-describe"
GROUP = 'lifecycle'
SERVICES = ['transfer']

@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListSecurityPolicies returns the built-in catalog and each name resolves via
    DescribeSecurityPolicy to a populated body with the Type implied by the name."""
    tf = ctx.client('transfer')
    names = tf.list_security_policies().get('SecurityPolicyNames', [])
    assert len(names) > 1, f'ListSecurityPolicies returned too few built-in policies: {names}'
    for target in (names[0], names[-1]):
        policy = tf.describe_security_policy(SecurityPolicyName=target)['SecurityPolicy']
        assert policy['SecurityPolicyName'] == target, policy
        expect_type = 'CONNECTOR' if 'ConnectorSecurityPolicy' in target else 'SERVER'
        assert policy.get('Type') == expect_type, (
            f'{target}: Type={policy.get("Type")!r}, expected {expect_type!r} from the name'
        )
        assert policy.get('SshCiphers'), f'{target}: SshCiphers empty/absent: {policy}'
        assert policy.get('SshKexs'), f'{target}: SshKexs empty/absent: {policy}'
if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
