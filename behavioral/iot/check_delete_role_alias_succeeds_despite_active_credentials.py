"""delete-role-alias-succeeds-despite-active-credentials."""
from __future__ import annotations

import http.client
import urllib.parse
import json
import os
import ssl
import tempfile
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "delete-role-alias-succeeds-despite-active-credentials"
GROUP = "negative-classes"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A role alias that has just vended credentials over the mTLS credentials provider
    can still be deleted: afterwards DescribeRoleAlias and UpdateRoleAlias fail with
    ResourceNotFoundException and their exact messages."""
    iot = ctx.client("iot")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    used_alias = ctx.unique_name("sim2real-ra-used-")
    unused_alias = ctx.unique_name("sim2real-ra-unused-")
    used_alias_arn = f"arn:aws:iot:{ctx.region}:{account_id}:rolealias/{used_alias}"

    role_name = ctx.unique_name("sim2real-ra-role-")
    role_arn = _create_credentials_role(ctx, iam, role_name, used_alias_arn)

    iot.create_role_alias(
        roleAlias=used_alias, roleArn=role_arn, credentialDurationSeconds=900
    )
    ctx.on_cleanup(lambda: _best_effort_delete_alias(iot, used_alias))

    iot.create_role_alias(
        roleAlias=unused_alias, roleArn=role_arn, credentialDurationSeconds=900
    )
    ctx.on_cleanup(lambda: _best_effort_delete_alias(iot, unused_alias))

    cert = iot.create_keys_and_certificate(setAsActive=True)
    cert_arn = cert["certificateArn"]
    cert_pem = cert["certificatePem"]
    private_key_pem = cert["keyPair"]["PrivateKey"]

    policy_name = ctx.unique_name("sim2real-ra-policy-")
    iot.create_policy(
        policyName=policy_name,
        policyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "iot:AssumeRoleWithCertificate",
                        "Resource": used_alias_arn,
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iot.delete_policy(policyName=policy_name))
    iot.attach_policy(policyName=policy_name, target=cert_arn)
    ctx.on_cleanup(lambda: _detach_deactivate_delete_cert(iot, policy_name, cert_arn))

    endpoint = iot.describe_endpoint(endpointType="iot:CredentialProvider")["endpointAddress"]

    creds_body = _fetch_credentials_with_retry(
        ctx, endpoint, used_alias, cert_pem, private_key_pem, timeout_s=45
    )
    creds = creds_body["credentials"]
    assert creds["accessKeyId"], "credentials-provider response had no accessKeyId"
    assert creds["secretAccessKey"], "credentials-provider response had no secretAccessKey"
    assert creds["sessionToken"], "credentials-provider response had no sessionToken"
    assert creds["expiration"], "credentials-provider response had no expiration"

    # the used alias now has a live, unexpired credential chain attached, but
    # AWS IoT does not block deletion on that basis alone
    iot.delete_role_alias(roleAlias=used_alias)
    code_after_used, message_after_used = _error(lambda: iot.describe_role_alias(roleAlias=used_alias))
    assert code_after_used == "ResourceNotFoundException", (
        f"expected the used alias to be gone after delete, got {code_after_used}"
    )
    expected = f"Role alias {used_alias} not found"
    assert message_after_used == expected, f"expected message {expected!r}, got {message_after_used!r}"
    update_code_after_used, update_message_after_used = _error(
        lambda: iot.update_role_alias(roleAlias=used_alias, credentialDurationSeconds=1800)
    )
    assert update_code_after_used == "ResourceNotFoundException", (
        f"expected a mutation on the deleted used alias to fail not-found, got {update_code_after_used}"
    )
    assert update_message_after_used == expected, (
        f"expected message {expected!r}, got {update_message_after_used!r}"
    )

    # positive control: an alias that was never used to mint credentials also deletes cleanly
    iot.delete_role_alias(roleAlias=unused_alias)
    code_after, message_after = _error(lambda: iot.describe_role_alias(roleAlias=unused_alias))
    assert code_after == "ResourceNotFoundException", (
        f"expected the unused alias to be gone after delete, got {code_after}"
    )
    expected = f"Role alias {unused_alias} not found"
    assert message_after == expected, f"expected message {expected!r}, got {message_after!r}"


def _error(fn):
    """``(code, message)`` of a call real AWS refuses; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS refuses this call, but it succeeded and returned {result!r}")


def _best_effort_delete_alias(iot, alias_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        iot.delete_role_alias(roleAlias=alias_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _detach_deactivate_delete_cert(iot, policy_name: str, cert_arn: str) -> None:
    from botocore.exceptions import ClientError

    cert_id = cert_arn.split("/")[-1]
    iot.detach_policy(policyName=policy_name, target=cert_arn)
    try:
        iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        iot.delete_certificate(certificateId=cert_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_credentials_role(ctx, iam, role_name: str, role_alias_arn: str) -> str:
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "credentials.iot.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"ArnEquals": {"aws:SourceArn": role_alias_arn}},
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    # IAM/IoT policy propagation lag (if any) is absorbed by the bounded retry
    # loop in _fetch_credentials_with_retry, so no fixed sleep is needed here.
    return role["Role"]["Arn"]


def _fetch_credentials_with_retry(
    ctx, endpoint: str, role_alias: str, cert_pem: str, private_key_pem: str, timeout_s: float
) -> dict:
    """POSTs to the mTLS credentials-provider endpoint, retrying while IAM/IoT
    policy attachment propagation (eventual consistency) still returns 403."""
    with tempfile.NamedTemporaryFile("w", suffix=".crt.pem", delete=False) as certf:
        certf.write(cert_pem)
        cert_path = certf.name
    with tempfile.NamedTemporaryFile("w", suffix=".key.pem", delete=False) as keyf:
        keyf.write(private_key_pem)
        key_path = keyf.name

    try:
        ssl_context = ssl.create_default_context()
        ssl_context.load_cert_chain(certfile=cert_path, keyfile=key_path)

        deadline = time.monotonic() + timeout_s
        last_error = None
        while time.monotonic() < deadline:
            # tls: the credentials provider authenticates with a client certificate (mutual TLS)
            _url = ctx.endpoint_url(endpoint)
            _t = urllib.parse.urlsplit(_url)
            conn = http.client.HTTPSConnection(_t.hostname, _t.port or 443, context=ssl_context, timeout=15)
            try:
                conn.request("GET", f"/role-aliases/{role_alias}/credentials")
                resp = conn.getresponse()
                body = resp.read()
            finally:
                conn.close()
            if resp.status == 200:
                return json.loads(body)
            last_error = f"HTTP {resp.status}: {body!r}"
            time.sleep(2)
        raise AssertionError(
            f"credentials-provider never returned 200 within {timeout_s}s: {last_error}"
        )
    finally:
        os.unlink(cert_path)
        os.unlink(key_path)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
