"""security-policy-catalog-is-fixed-reference-data."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "security-policy-catalog-is-fixed-reference-data"
GROUP = 'lifecycle'
SERVICES = ['transfer']

# AWS-maintained security-policy names that must exist in every account/region: a subset of
# the catalog covering each vintage and the FIPS, Restricted and connector variants.
_MUST_EXIST = (
    'TransferSecurityPolicy-2018-11',
    'TransferSecurityPolicy-2020-06',
    'TransferSecurityPolicy-2022-03',
    'TransferSecurityPolicy-2023-05',
    'TransferSecurityPolicy-2024-01',
    'TransferSecurityPolicy-FIPS-2020-06',
    'TransferSecurityPolicy-FIPS-2023-05',
    'TransferSecurityPolicy-Restricted-2018-11',
    'TransferSFTPConnectorSecurityPolicy-2023-07',
)

# smithy SecurityPolicyName pattern, com.amazonaws.transfer#SecurityPolicyName.
_NAME_RE = re.compile(r'^Transfer[A-Za-z0-9]*SecurityPolicy-[A-Za-z0-9-]+$')


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListSecurityPolicies returns the fixed AWS catalog including known vintages; every name
    resolves via DescribeSecurityPolicy to populated SSH algorithms, with Fips and Type
    (CONNECTOR vs SERVER) matching the name.
    """
    tf = ctx.client('transfer')

    # ListSecurityPolicies is paginated (NextToken/MaxResults); a single un-paginated call would
    # silently see only the first page and misreport the catalog as short if AWS ever truncates it.
    names = []
    for page in tf.get_paginator('list_security_policies').paginate():
        names.extend(page.get('SecurityPolicyNames', []))
    assert len(names) == len(set(names)), f"ListSecurityPolicies returned duplicates: {names}"
    assert len(names) >= 20, (
        f"expected the AWS catalog of >=20 built-in security policies, got {len(names)}: {names}"
    )
    missing = [n for n in _MUST_EXIST if n not in names]
    assert not missing, f"AWS-maintained security policies absent from the catalog: {missing}"
    bad_shape = [n for n in names if not _NAME_RE.match(n)]
    assert not bad_shape, f"catalog names violate the SecurityPolicyName pattern: {bad_shape}"

    # EVERY catalog entry must resolve — not just one. A catalog whose names are unresolvable
    # is a name list, not reference data.
    for name in names:
        policy = tf.describe_security_policy(SecurityPolicyName=name)['SecurityPolicy']
        assert policy['SecurityPolicyName'] == name, (
            f"DescribeSecurityPolicy({name}) echoed {policy.get('SecurityPolicyName')!r}"
        )
        expect_type = 'CONNECTOR' if 'ConnectorSecurityPolicy' in name else 'SERVER'
        assert policy.get('Type') == expect_type, (
            f"{name}: Type={policy.get('Type')!r}, expected {expect_type!r}"
        )
        expect_fips = '-FIPS-' in name
        assert policy.get('Fips') is expect_fips, (
            f"{name}: Fips={policy.get('Fips')!r}, expected {expect_fips} from the policy name"
        )
        assert policy.get('SshCiphers'), f"{name}: SshCiphers empty/absent: {policy}"
        assert policy.get('SshKexs'), f"{name}: SshKexs empty/absent: {policy}"
        assert policy.get('SshMacs'), f"{name}: SshMacs empty/absent: {policy}"

    # One current policy body, asserted in detail.
    pinned = tf.describe_security_policy(
        SecurityPolicyName='TransferSecurityPolicy-2024-01'
    )['SecurityPolicy']
    assert set(pinned.get('Protocols') or []) == {'SFTP', 'FTPS'}, (
        f"TransferSecurityPolicy-2024-01 Protocols={pinned.get('Protocols')!r}, expected SFTP+FTPS"
    )
    assert pinned.get('TlsCiphers'), (
        f"TransferSecurityPolicy-2024-01 covers FTPS so TlsCiphers must be populated: {pinned}"
    )
    assert 'aes256-ctr' in (pinned.get('SshCiphers') or []), (
        f"TransferSecurityPolicy-2024-01 SshCiphers missing aes256-ctr: {pinned.get('SshCiphers')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
