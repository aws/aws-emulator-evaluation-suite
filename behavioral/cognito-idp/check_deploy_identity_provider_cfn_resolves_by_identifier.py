"""deploy-identity-provider-cfn-resolves-by-identifier."""
from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "deploy-identity-provider-cfn-resolves-by-identifier"
GROUP = "deploy"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed SAML UserPoolIdentityProvider resolves by its IdpIdentifier to the declared
    name, type and metadata, matching DescribeIdentityProvider for the same provider."""
    entity_id = f"https://sim2real-testing.example.com/saml/{ctx.unique_name('metadata-')}"
    cert_b64 = _generate_self_signed_cert_b64(ctx)
    metadata_xml = (
        "<?xml version='1.0'?>"
        f"<EntityDescriptor xmlns='urn:oasis:names:tc:SAML:2.0:metadata' entityID='{entity_id}'>"
        "<IDPSSODescriptor protocolSupportEnumeration='urn:oasis:names:tc:SAML:2.0:protocol'>"
        "<KeyDescriptor use='signing'>"
        "<ds:KeyInfo xmlns:ds='http://www.w3.org/2000/09/xmldsig#'>"
        "<ds:X509Data>"
        f"<ds:X509Certificate>{cert_b64}</ds:X509Certificate>"
        "</ds:X509Data>"
        "</ds:KeyInfo>"
        "</KeyDescriptor>"
        "<SingleSignOnService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'"
        " Location='https://sim2real-testing.example.com/saml/sso'/>"
        "</IDPSSODescriptor>"
        "</EntityDescriptor>"
    )

    provider_name = ctx.unique_name("sim2real-saml-")[:32]  # ProviderName is capped at 32 chars
    idp_identifier = ctx.unique_name("sim2real-idp-")[:40]  # IdpIdentifier is capped at 40 chars

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "UserPool": {
                "Type": "AWS::Cognito::UserPool",
                "Properties": {"UserPoolName": ctx.unique_name("sim2real-cog-idp-pool-")},
            },
            "IdentityProvider": {
                "Type": "AWS::Cognito::UserPoolIdentityProvider",
                "Properties": {
                    "UserPoolId": {"Ref": "UserPool"},
                    "ProviderName": provider_name,
                    "ProviderType": "SAML",
                    "ProviderDetails": {"MetadataFile": metadata_xml, "IDPInit": "true"},
                    "IdpIdentifiers": [idp_identifier],
                },
            },
        },
        "Outputs": {"UserPoolId": {"Value": {"Ref": "UserPool"}}},
    }
    outputs = _deploy_cfn_stack(ctx, template)
    pool_id = outputs["UserPoolId"]

    cognito = ctx.client("cognito-idp")

    by_identifier = cognito.get_identity_provider_by_identifier(
        UserPoolId=pool_id, IdpIdentifier=idp_identifier
    )["IdentityProvider"]
    assert by_identifier["ProviderName"] == provider_name
    assert by_identifier["ProviderType"] == "SAML"
    assert entity_id in by_identifier["ProviderDetails"]["MetadataFile"]
    assert idp_identifier in by_identifier["IdpIdentifiers"]

    described = cognito.describe_identity_provider(UserPoolId=pool_id, ProviderName=provider_name)[
        "IdentityProvider"
    ]
    assert described["ProviderName"] == by_identifier["ProviderName"]
    assert entity_id in described["ProviderDetails"]["MetadataFile"]


def _generate_self_signed_cert_b64(ctx) -> str:
    """Generate a throwaway self-signed X.509 cert (base64 DER, no PEM headers) via openssl."""
    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = Path(tmpdir) / "key.pem"
        cert_path = Path(tmpdir) / "cert.pem"
        require_tools("openssl")
        proc = subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                str(key_path),
                "-out",
                str(cert_path),
                "-days",
                "365",
                "-nodes",
                "-subj",
                "/CN=sim2real-saml-idp",
            ],
            capture_output=True,
            text=True,
            env=ctx.subprocess_env(),
        )
        if proc.returncode != 0:
            raise AssertionError(f"openssl failed to generate a self-signed cert: {proc.stderr}")
        pem_lines = cert_path.read_text().splitlines()
        b64_lines = [
            line
            for line in pem_lines
            if line and "BEGIN CERTIFICATE" not in line and "END CERTIFICATE" not in line
        ]
        return "".join(b64_lines)


def _deploy_cfn_stack(ctx, template: dict) -> dict:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-cog-stack-")

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
