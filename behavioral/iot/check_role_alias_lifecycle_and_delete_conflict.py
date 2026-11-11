"""role-alias-lifecycle-and-delete-conflict."""
from __future__ import annotations

import json
import os
import ssl
import tempfile
import time
from http.client import HTTPSConnection
import urllib.parse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "role-alias-lifecycle-and-delete-conflict"
GROUP = "state-machine"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A role alias round-trips credentialDurationSeconds and works via the credentials provider
    over mutual TLS; attached policy/ACTIVE cert deletes are refused until released, then
    DeleteRoleAlias removes the alias (a later UpdateRoleAlias fails)."""
    iam = ctx.client("iam")
    iot = ctx.client("iot")

    role_name = ctx.unique_name("sim2real-iot-rolealias-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "credentials.iot.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resource_tags = [{"Key": "simparity-check", "Value": CHECK}]
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=resource_tags,
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]

    role_alias = ctx.unique_name("sim2real-iot-rolealias-")

    create_resp = _retry_on_codes(
        lambda: iot.create_role_alias(
            roleAlias=role_alias,
            roleArn=role_arn,
            credentialDurationSeconds=900,
            tags=resource_tags,
        ),
        codes=("InvalidRequestException",),
        timeout_s=45,
    )
    role_alias_arn = create_resp["roleAliasArn"]

    described = iot.describe_role_alias(roleAlias=role_alias)["roleAliasDescription"]
    assert described["credentialDurationSeconds"] == 900, (
        f"expected credentialDurationSeconds=900 after create, got {described['credentialDurationSeconds']!r}"
    )
    assert described["roleArn"] == role_arn, f"expected roleArn={role_arn!r}, got {described['roleArn']!r}"

    iot.update_role_alias(roleAlias=role_alias, credentialDurationSeconds=1800)
    described = iot.describe_role_alias(roleAlias=role_alias)["roleAliasDescription"]
    assert described["credentialDurationSeconds"] == 1800, (
        f"expected credentialDurationSeconds=1800 after update, got {described['credentialDurationSeconds']!r}"
    )

    cert_resp = iot.create_keys_and_certificate(setAsActive=True)
    cert_arn = cert_resp["certificateArn"]
    cert_id = cert_resp["certificateId"]
    cert_pem = cert_resp["certificatePem"]
    private_key = cert_resp["keyPair"]["PrivateKey"]
    ctx.on_cleanup(lambda: _safe_deactivate_delete_cert(iot, cert_id))

    policy_name = ctx.unique_name("sim2real-iot-rolealias-pol-")
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iot:AssumeRoleWithCertificate",
                "Resource": role_alias_arn,
            }
        ],
    }
    iot.create_policy(
        policyName=policy_name, policyDocument=json.dumps(policy_doc), tags=resource_tags
    )
    ctx.on_cleanup(lambda: _safe_delete_policy(iot, policy_name))
    iot.attach_policy(policyName=policy_name, target=cert_arn)
    ctx.on_cleanup(lambda: _safe_detach_policy(iot, policy_name, cert_arn))

    endpoint = iot.describe_endpoint(endpointType="iot:CredentialProvider")["endpointAddress"]
    creds = _fetch_role_alias_credentials(ctx, endpoint, role_alias, cert_pem, private_key)
    assert {"accessKeyId", "secretAccessKey", "sessionToken"}.issubset(creds.keys()), (
        f"credentials-provider response missing expected keys, got {sorted(creds.keys())!r}"
    )

    # delete-conflict: a policy still attached to a certificate cannot be deleted
    code, code_message = _error(lambda: iot.delete_policy(policyName=policy_name))
    assert code == "DeleteConflictException", (
        f"expected DeleteConflictException deleting a policy still attached to a certificate, got {code!r}"
    )
    assert code_message == f"The policy cannot be deleted as the policy is attached to one or more principals (name={policy_name})", (
        f"expected the exact {code} message, got {code_message!r}"
    )
    still_there = iot.get_policy(policyName=policy_name)
    assert still_there["policyName"] == policy_name, "policy must still exist after the rejected delete"

    # delete-conflict: an ACTIVE certificate cannot be deleted
    code, code_message = _error(lambda: iot.delete_certificate(certificateId=cert_id))
    assert code == "CertificateStateException", (
        f"expected CertificateStateException deleting an ACTIVE certificate, got {code!r}"
    )
    assert code_message == f"Certificate must be deactivated (not ACTIVE) before deletion. Id: {cert_id}", (
        f"expected the exact {code} message, got {code_message!r}"
    )
    still_active = iot.describe_certificate(certificateId=cert_id)["certificateDescription"]
    assert still_active["status"] == "ACTIVE", (
        f"certificate must remain ACTIVE after the rejected delete, got {still_active['status']!r}"
    )

    # release the attachments in clean order (the restore leg), then delete succeeds
    iot.detach_policy(policyName=policy_name, target=cert_arn)
    iot.delete_policy(policyName=policy_name)
    iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE")
    iot.delete_certificate(certificateId=cert_id)

    iot.delete_role_alias(roleAlias=role_alias)
    code, code_message = _error(lambda: iot.describe_role_alias(roleAlias=role_alias))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {code!r}"
    assert code_message == f"Role alias {role_alias} not found", (
        f"expected the exact {code} message, got {code_message!r}"
    )

    # a mutation on the dead alias also fails
    code, code_message = _error(
        lambda: iot.update_role_alias(roleAlias=role_alias, credentialDurationSeconds=1800)
    )
    assert code == "ResourceNotFoundException", (
        f"expected UpdateRoleAlias on a deleted alias to fail with ResourceNotFoundException, got {code!r}"
    )
    assert code_message == f"Role alias {role_alias} not found", (
        f"expected the exact {code} message, got {code_message!r}"
    )



def _fetch_role_alias_credentials(ctx, endpoint: str, role_alias: str, cert_pem: str, private_key: str) -> dict:
    cert_fd, cert_path = tempfile.mkstemp(suffix=".pem")
    key_fd, key_path = tempfile.mkstemp(suffix=".key")
    try:
        with os.fdopen(cert_fd, "w") as f:
            f.write(cert_pem)
        with os.fdopen(key_fd, "w") as f:
            f.write(private_key)

        context = ssl.create_default_context()
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)

        deadline = time.monotonic() + 90.0
        last_exc = None
        while time.monotonic() < deadline:
            try:
                # tls: the credentials provider authenticates with a client certificate (mutual TLS)
                _url = ctx.endpoint_url(endpoint)
                _t = urllib.parse.urlsplit(_url)
                conn = HTTPSConnection(_t.hostname, _t.port or 443, context=context, timeout=15)
                conn.request(
                    "GET",
                    f"/role-aliases/{role_alias}/credentials",
                )
                resp = conn.getresponse()
                body = resp.read()
                conn.close()
                if resp.status == 200:
                    return json.loads(body)["credentials"]
                last_exc = AssertionError(
                    f"credentials endpoint returned {resp.status}: {body!r}"
                )
            except OSError as exc:
                last_exc = exc
            time.sleep(3)
        raise last_exc
    finally:
        for path in (cert_path, key_path):
            try:
                os.unlink(path)
            except OSError:
                pass


def _safe_deactivate_delete_cert(iot, cert_id):
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


def _safe_delete_policy(iot, policy_name):
    try:
        iot.delete_policy(policyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_detach_policy(iot, policy_name, target):
    iot.detach_policy(policyName=policy_name, target=target)


def _retry_on_codes(fn, codes, timeout_s=45.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in codes:
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _error(fn) -> tuple[str, str]:
    """Call fn(); return the ClientError (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
