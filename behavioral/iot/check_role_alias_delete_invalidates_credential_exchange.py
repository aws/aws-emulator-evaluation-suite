"""role-alias-delete-invalidates-credential-exchange."""
from __future__ import annotations

import json
import os
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "role-alias-delete-invalidates-credential-exchange"
GROUP = "state-machine"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A certificate that exchanged its role alias for credentials gets a 400/404 from the
    credentials-provider endpoint on the very next request after DeleteRoleAlias (no grace)."""
    import requests

    iot = ctx.client("iot")
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-rolealias-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "credentials.iot.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    alias_name = ctx.unique_name("sim2real-rolealias-")
    alias_created = iot.create_role_alias(
        roleAlias=alias_name,
        roleArn=role_arn,
        credentialDurationSeconds=900,
        tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    alias_arn = alias_created["roleAliasArn"]
    alias_deleted = {"done": False}

    def _cleanup_alias():
        if not alias_deleted["done"]:
            try:
                iot.delete_role_alias(roleAlias=alias_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise

    ctx.on_cleanup(_cleanup_alias)

    cert = iot.create_keys_and_certificate(setAsActive=True)
    cert_arn = cert["certificateArn"]
    ctx.on_cleanup(lambda: _deactivate_and_delete_cert(iot, cert_arn))

    policy_name = ctx.unique_name("sim2real-rolealias-policy-")
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "iot:AssumeRoleWithCertificate", "Resource": alias_arn}],
    }
    iot.create_policy(
        policyName=policy_name,
        policyDocument=json.dumps(policy_doc),
        tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iot.delete_policy(policyName=policy_name))
    iot.attach_policy(policyName=policy_name, target=cert_arn)
    ctx.on_cleanup(lambda: iot.detach_policy(policyName=policy_name, target=cert_arn))

    endpoint = iot.describe_endpoint(endpointType="iot:CredentialProvider")["endpointAddress"]
    url = f"{ctx.endpoint_url(endpoint)}/role-aliases/{alias_name}/credentials"

    cert_file = tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False)
    key_file = tempfile.NamedTemporaryFile(mode="w", suffix=".key", delete=False)
    try:
        cert_file.write(cert["certificatePem"])
        cert_file.flush()
        key_file.write(cert["keyPair"]["PrivateKey"])
        key_file.flush()
        cert_file.close()
        key_file.close()

        # IAM trust and IoT policy attachment propagate eventually; poll for the first exchange
        deadline = time.monotonic() + 90.0
        response = None
        while time.monotonic() < deadline:
            try:
                response = requests.get(url, cert=(cert_file.name, key_file.name), timeout=10, verify=ctx.http_verify)
                if response.status_code == 200:
                    break
            except requests.exceptions.RequestException:
                pass
            time.sleep(3.0)

        assert response is not None and response.status_code == 200, (
            f"credential exchange never succeeded via active role alias, last={getattr(response, 'status_code', None)}"
        )
        body = response.json()
        assert "credentials" in body and "accessKeyId" in body["credentials"], (
            f"credential exchange body missing credentials/accessKeyId, got keys={list(body.keys())}"
        )

        iot.delete_role_alias(roleAlias=alias_name)
        alias_deleted["done"] = True

        control_plane_code, control_plane_code_message = _error(lambda: iot.describe_role_alias(roleAlias=alias_name))
        assert control_plane_code == "ResourceNotFoundException", (
            f"expected DescribeRoleAlias to report ResourceNotFoundException after delete, got {control_plane_code}"
        )
        assert control_plane_code_message == f"Role alias {alias_name} not found", (
            f"expected the exact {control_plane_code} message, got {control_plane_code_message!r}"
        )

        # AWS answers either 404 (alias gone) or 400 "unable to assume the role" (role
        # resolution races the delete); both are immediate rejections, never a 200.
        post_delete = requests.get(url, cert=(cert_file.name, key_file.name), timeout=10, verify=ctx.http_verify)
        assert post_delete.status_code in (400, 404), (
            f"expected the credentials-provider endpoint to immediately reject a deleted role alias "
            f"with 400 or 404 (no cached-TTL grace period), got {post_delete.status_code}: {post_delete.text[:300]!r}"
        )
    finally:
        os.unlink(cert_file.name)
        os.unlink(key_file.name)


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _deactivate_and_delete_cert(iot, cert_arn: str) -> None:
    cert_id = cert_arn.split("/")[-1]
    try:
        iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        iot.delete_certificate(certificateId=cert_id, forceDelete=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
