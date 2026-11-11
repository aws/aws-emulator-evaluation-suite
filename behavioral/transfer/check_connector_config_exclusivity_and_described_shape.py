"""connector-config-exclusivity-and-described-shape."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "connector-config-exclusivity-and-described-shape"
GROUP = 'overly-permissive'
SERVICES = ['transfer']


# ===== helpers =====
def _err(fn):
    """Return (code, message) for a ClientError; raise AssertionError if the call succeeded."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _connector_ids(tf, urls):
    """Ids of the listed connectors whose Url is one this check minted."""
    out = set()
    for page in tf.get_paginator('list_connectors').paginate():
        for c in page.get('Connectors', []):
            if c.get('Url') in urls:
                out.add(c['ConnectorId'])
    return out


def _delete_connector_if_present(tf, connector_id):
    try:
        tf.delete_connector(ConnectorId=connector_id)
    except ClientError as exc:
        if exc.response['Error']['Code'] != 'ResourceNotFoundException':
            raise


def _create_access_role(ctx):
    iam = ctx.client('iam')
    role_name = ctx.unique_name('sim2real-behav-transfer-conn-')
    trust = {'Version': '2012-10-17', 'Statement': [{
        'Effect': 'Allow', 'Principal': {'Service': 'transfer.amazonaws.com'},
        'Action': 'sts:AssumeRole'}]}
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{'Key': 'sim2real', 'Value': CHECK}])['Role']['Arn']
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateConnector requires exactly one of As2Config/SftpConfig and names each missing AS2
    member, and DescribeConnector returns the populated connector with its required Status and
    EgressType and the AS2 defaults the service fills in.
    """
    tf = ctx.client('transfer')

    local_id = tf.create_profile(
        As2Id=ctx.unique_name('sim2real-behav-as2-local-'), ProfileType='LOCAL',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}])['ProfileId']
    ctx.on_cleanup(lambda _p=local_id: tf.delete_profile(ProfileId=_p))
    partner_id = tf.create_profile(
        As2Id=ctx.unique_name('sim2real-behav-as2-partner-'), ProfileType='PARTNER',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}])['ProfileId']
    ctx.on_cleanup(lambda _p=partner_id: tf.delete_profile(ProfileId=_p))

    access_role = _create_access_role(ctx)

    # Compression / EncryptionAlgorithm / SigningAlgorithm are NOT service-defaulted: real AWS
    # refuses CreateConnector without each of them in turn (asserted below). Only
    # MdnSigningAlgorithm and PreserveContentType are filled in by the service.
    as2_config = {'LocalProfileId': local_id, 'PartnerProfileId': partner_id,
                  'MdnResponse': 'NONE', 'Compression': 'DISABLED',
                  'EncryptionAlgorithm': 'NONE', 'SigningAlgorithm': 'NONE'}
    sftp_config = {'MaxConcurrentConnections': 1}
    # Real AWS validates the Url: the RFC 2606 `.invalid` TLD is refused with "The specified Url
    # is not valid", so the accepted url uses the RFC 2606 `example.com` documentation domain
    # (inert -- no transfer is ever started, so nothing is dialled).
    host = ctx.unique_name('sim2real-behav-')
    url = f'https://{host}.example.com/as2'
    bad_url = f'https://{host}.invalid/as2'
    own_urls = {url, bad_url}

    before = _connector_ids(tf, own_urls)
    assert before == set(), before

    code_both, msg_both = _err(lambda: tf.create_connector(
        Url=url, AccessRole=access_role, As2Config=as2_config, SftpConfig=sftp_config))
    assert (code_both, msg_both) == (
        'InvalidRequestException', 'Only one of As2Config or SftpConfig must be specified'), (
        f"CreateConnector with BOTH As2Config and SftpConfig must be rejected, "
        f"got {code_both!r}: {msg_both!r}"
    )

    code_none, msg_none = _err(lambda: tf.create_connector(Url=url, AccessRole=access_role))
    assert (code_none, msg_none) == (
        'InvalidRequestException', 'One of As2Config or SftpConfig must be specified'), (
        f"CreateConnector with NEITHER As2Config nor SftpConfig must be rejected, "
        f"got {code_none!r}: {msg_none!r}"
    )

    # An otherwise-valid AS2 connector with an unusable Url is refused, and the diagnostic names
    # the Url rather than the config. AWS runs the
    # exclusivity check FIRST, so this leg must send exactly one config to reach the Url.
    code_url, msg_url = _err(lambda: tf.create_connector(
        Url=bad_url, AccessRole=access_role, As2Config=as2_config))
    assert (code_url, msg_url) == ('InvalidRequestException', 'The specified Url is not valid'), (
        f"CreateConnector with an unresolvable Url must be rejected naming the Url, "
        f"got {code_url!r}: {msg_url!r}"
    )

    # Each AS2 algorithm member is INDIVIDUALLY required and the diagnostic names the one that is
    # missing -- so an emulator cannot satisfy this with one generic "As2Config is invalid".
    required_as2 = ('Compression', 'EncryptionAlgorithm', 'SigningAlgorithm')
    for field in required_as2:
        partial = {k: v for k, v in as2_config.items() if k != field}
        code_missing, msg_missing = _err(lambda _p=partial: tf.create_connector(
            Url=url, AccessRole=access_role, As2Config=_p))
        assert (code_missing, msg_missing) == (
            'InvalidRequestException', f'{field} is required in As2Config'), (
            f"CreateConnector without As2Config.{field} must be rejected naming {field}, "
            f"got {code_missing!r}: {msg_missing!r}"
        )

    after_reject = _connector_ids(tf, own_urls)
    assert after_reject == before, (
        f"rejected CreateConnector calls leaked connectors: {sorted(after_reject - before)}"
    )

    # Control: exactly one transport config is accepted, and the described shape is populated.
    cid = tf.create_connector(
        Url=url, AccessRole=access_role, As2Config=as2_config,
        Tags=[{'Key': 'sim2real', 'Value': CHECK}])['ConnectorId']
    ctx.on_cleanup(lambda _c=cid: _delete_connector_if_present(tf, _c))

    conn = tf.describe_connector(ConnectorId=cid)['Connector']
    assert conn['ConnectorId'] == cid, conn
    assert f':connector/{cid}' in conn['Arn'], conn['Arn']
    assert conn['Url'] == url, f"Url not echoed: {conn.get('Url')!r}"
    assert conn['AccessRole'] == access_role, conn.get('AccessRole')
    assert 'SftpConfig' not in conn, (
        f"an AS2 connector must not describe an SftpConfig: {conn.get('SftpConfig')!r}"
    )
    assert conn.get('Status') in ('ACTIVE', 'ERRORED', 'PENDING'), (
        f"DescribedConnector.Status is a required ConnectorStatus member; got "
        f"{conn.get('Status')!r}"
    )
    # DescribedConnector.EgressType is @required but also carries @default("SERVICE_MANAGED"), and
    # real AWS OMITS it from the wire for a service-managed connector -- Smithy elides
    # default-valued members. So SERVICE_MANAGED egress is asserted
    # through its three observable consequences instead: no EgressType on the wire, no
    # EgressConfig union (that member is populated only for VPC_LATTICE), and a non-empty list of
    # service-managed egress IPs. An emulator that invents a VPC_LATTICE egress, or that returns
    # no egress IPs at all, fails.
    assert 'EgressType' not in conn, (
        f"a SERVICE_MANAGED connector elides the defaulted EgressType member, got "
        f"{conn.get('EgressType')!r}"
    )
    assert 'EgressConfig' not in conn, (
        f"EgressConfig is populated only for VPC_LATTICE egress, got {conn.get('EgressConfig')!r}"
    )
    egress_ips = conn.get('ServiceManagedEgressIpAddresses')
    assert isinstance(egress_ips, list) and egress_ips, (
        f"a SERVICE_MANAGED connector must report its egress IPs, got {egress_ips!r}"
    )
    assert all(ip.count('.') == 3 for ip in egress_ips), (
        f"ServiceManagedEgressIpAddresses must be IPv4 dotted quads, got {egress_ips!r}"
    )

    as2 = conn['As2Config']
    assert as2['LocalProfileId'] == local_id, as2
    assert as2['PartnerProfileId'] == partner_id, as2
    assert as2['MdnResponse'] == 'NONE', as2
    # The three individually-required algorithm members are echoed exactly as sent.
    for field in required_as2:
        assert as2.get(field) == as2_config[field], (
            f"As2Config.{field} not echoed: sent {as2_config[field]!r}, got {as2.get(field)!r}"
        )
    # The ONLY service-computed As2Config defaults on real AWS -- the
    # request never carried either.
    assert as2.get('MdnSigningAlgorithm') == 'DEFAULT', (
        f"As2Config.MdnSigningAlgorithm must be defaulted to DEFAULT, got "
        f"{as2.get('MdnSigningAlgorithm')!r}"
    )
    assert as2.get('PreserveContentType') == 'DISABLED', (
        f"As2Config.PreserveContentType must be defaulted to DISABLED, got "
        f"{as2.get('PreserveContentType')!r}"
    )

    tf.delete_connector(ConnectorId=cid)
    gone = _err(lambda: tf.describe_connector(ConnectorId=cid))
    assert gone == ('ResourceNotFoundException', 'Unknown connector'), (
        f"DescribeConnector after delete must raise ResourceNotFoundException, got {gone!r}"
    )
    assert cid not in _connector_ids(tf, own_urls), f"deleted connector {cid} still listed"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
