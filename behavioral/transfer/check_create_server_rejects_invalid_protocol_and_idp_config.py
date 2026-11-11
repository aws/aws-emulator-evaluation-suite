"""create-server-rejects-invalid-protocol-and-idp-config."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-server-rejects-invalid-protocol-and-idp-config"
GROUP = 'overly-permissive'
SERVICES = ['transfer']


# ===== helpers =====
def _err(fn):
    """Return (code, message) for a ClientError. An unexpected SUCCESS raises, because
    accepting a config real AWS refuses must fail as such, not as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message') or ''
    raise AssertionError(
        f"real AWS rejects this CreateServer config, but it SUCCEEDED and returned {result!r}")


def _server_ids(tf):
    out = set()
    for page in tf.get_paginator('list_servers').paginate():
        for s in page.get('Servers', []):
            out.add(s['ServerId'])
    return out


def _tagged_servers(transfer, ids, key, value) -> list[str]:
    """The servers among ids tagged key=value; one already deleted is not this check's, since
    this check deletes nothing before its teardown."""
    own = []
    for server_id in sorted(ids):
        try:
            server = transfer.describe_server(ServerId=server_id)["Server"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                continue
            raise
        if {"Key": key, "Value": value} in server.get("Tags", []):
            own.append(server_id)
    return own


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateServer refuses FTP with SERVICE_MANAGED, VPC without EndpointDetails and
    API_GATEWAY without IdentityProviderDetails, each with its own message, and leaves no server.
    """
    tf = ctx.client('transfer')
    before = _server_ids(tf)
    marker = ctx.unique_name('sim2real-behav-refused-srv-')
    marker_tags = [{'Key': 'Name', 'Value': marker}]

    # Defect 1: add FTP to the baseline's protocol list, changing nothing else.
    code_ftp, msg_ftp = _err(lambda: tf.create_server(
        Protocols=['SFTP', 'FTP'],
        EndpointType='PUBLIC',
        IdentityProviderType='SERVICE_MANAGED',
        Tags=marker_tags,
    ))
    assert code_ftp == 'InvalidRequestException', (
        f"FTP under IdentityProviderType=SERVICE_MANAGED must be rejected with "
        f"InvalidRequestException, got {code_ftp!r}: {msg_ftp!r}"
    )
    assert msg_ftp == (
        'FTP and FTPS protocols unsupported for IdentityProviderType SERVICE_MANAGED'
    ), f"unexpected FTP refusal diagnostic: {msg_ftp!r}"

    # FTPS collapses to the SAME diagnostic: real AWS gates the FTP/FTPS FAMILY on the identity
    # provider, so the per-protocol rules (VPC endpoint for FTP, ACM Certificate for FTPS) are
    # never reached from a SERVICE_MANAGED baseline. Asserted as an equality because an emulator
    # that invents two different per-protocol messages here is not reproducing real AWS.
    code_ftps, msg_ftps = _err(lambda: tf.create_server(
        Protocols=['SFTP', 'FTPS'],
        EndpointType='PUBLIC',
        IdentityProviderType='SERVICE_MANAGED',
        Tags=marker_tags,
    ))
    assert code_ftps == 'InvalidRequestException', (
        f"FTPS under IdentityProviderType=SERVICE_MANAGED must be rejected with "
        f"InvalidRequestException, got {code_ftps!r}: {msg_ftps!r}"
    )
    assert msg_ftps == msg_ftp, (
        f"FTP and FTPS share ONE family-level refusal under SERVICE_MANAGED; got "
        f"{msg_ftps!r} vs {msg_ftp!r}"
    )

    # Defect 2: switch EndpointType to VPC, changing nothing else.
    code_vpc, msg_vpc = _err(lambda: tf.create_server(
        Protocols=['SFTP'],
        EndpointType='VPC',
        IdentityProviderType='SERVICE_MANAGED',
        Tags=marker_tags,
    ))
    assert code_vpc == 'InvalidRequestException', (
        f"EndpointType=VPC with no EndpointDetails must be rejected with "
        f"InvalidRequestException, got {code_vpc!r}: {msg_vpc!r}"
    )
    assert msg_vpc == 'EndpointDetails required for VPC', (
        f"unexpected VPC refusal diagnostic: {msg_vpc!r}"
    )

    # Defect 3: switch IdentityProviderType, changing nothing else. The diagnostic NAMES the
    # provider, so all three detail-requiring providers are individually distinguishable -- an
    # emulator with one generic "IdentityProviderDetails required" fails the distinctness check.
    idp_msgs = {}
    for idp in ('API_GATEWAY', 'AWS_LAMBDA', 'AWS_DIRECTORY_SERVICE'):
        code_idp, msg_idp = _err(lambda _i=idp: tf.create_server(
            Protocols=['SFTP'],
            EndpointType='PUBLIC',
            IdentityProviderType=_i,
            Tags=marker_tags,
        ))
        assert code_idp == 'InvalidRequestException', (
            f"IdentityProviderType={idp} with no IdentityProviderDetails must be rejected with "
            f"InvalidRequestException, got {code_idp!r}: {msg_idp!r}"
        )
        assert msg_idp == f'IdentityProviderDetails required for IdentityProviderType: {idp}', (
            f"the missing-details refusal for {idp} must name {idp}, got {msg_idp!r}"
        )
        idp_msgs[idp] = msg_idp
    assert len(set(idp_msgs.values())) == 3, (
        f"the three detail-requiring identity providers must produce three distinct "
        f"diagnostics, got {idp_msgs}"
    )

    # Three distinct defects must be three distinct diagnostics. Transfer returns
    # InvalidRequestException for all of these semantic rejections, so only the message tells
    # the three defects apart.
    msgs = [msg_ftp, msg_vpc, idp_msgs['API_GATEWAY']]
    assert all(msgs), f"an InvalidRequestException carried no Message: {msgs}"
    assert len(set(msgs)) == 3, (
        f"three distinct CreateServer defects produced indistinguishable diagnostics: {msgs}"
    )

    # Effect absent — and this is the assertion that matters financially: no billable
    # endpoint was created by any refused request.
    leaked = _tagged_servers(tf, _server_ids(tf) - before, 'Name', marker)
    assert leaked == [], f"rejected CreateServer calls leaked billable servers: {leaked}"

    # Liveness control: the service is still answering and the reference-data read that needs
    # no server still resolves, so the three refusals are not a blanket outage.
    assert isinstance(tf.list_servers().get('Servers'), list), tf.list_servers()
    policy = tf.describe_security_policy(
        SecurityPolicyName='TransferSecurityPolicy-2024-01'
    )['SecurityPolicy']
    assert policy['SecurityPolicyName'] == 'TransferSecurityPolicy-2024-01', policy


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
