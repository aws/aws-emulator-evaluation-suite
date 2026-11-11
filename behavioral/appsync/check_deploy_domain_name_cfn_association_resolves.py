"""deploy-domain-name-cfn-association-resolves."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time

from behavioral_harness import tags

CHECK = "deploy-domain-name-cfn-association-resolves"
GROUP = "deploy"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CFN DomainName with a private-CA-signed imported cert fails and the stack rolls back.

    DomainNameRes is CREATE_FAILED with "Certificate is invalid", GraphQLApi in the same stack
    reaches CREATE_COMPLETE first, and the domain is neither found nor listed afterwards.
    """
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    domain_name = _synthetic_domain(ctx)
    cert_arn = _import_ca_signed_cert(ctx, domain_name)

    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-appsync-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(_domain_template()),
        Parameters=[
            {"ParameterKey": "ApiName", "ParameterValue": ctx.unique_name("sim2real-domainapi-")},
            {"ParameterKey": "DomainNameParam", "ParameterValue": domain_name},
            {"ParameterKey": "CertificateArnParam", "ParameterValue": cert_arn},
        ],
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))

    from botocore.exceptions import ClientError, WaiterError

    try:
        cfn.get_waiter("stack_create_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )
        raise AssertionError(
            f"stack {stack_name} reached CREATE_COMPLETE -- expected DomainNameRes to be "
            "rejected for a certificate this account cannot get domain-validated by ACM"
        )
    except WaiterError:
        pass  # expected: the stack rolls back on the certificate-trust rejection

    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert stack["StackStatus"] == "ROLLBACK_COMPLETE", stack["StackStatus"]

    events_by_id: dict[str, list] = {}
    for event in cfn.describe_stack_events(StackName=stack_name)["StackEvents"]:
        events_by_id.setdefault(event["LogicalResourceId"], []).append(event)

    domain_failure = next(
        (e for e in events_by_id.get("DomainNameRes", []) if e["ResourceStatus"] == "CREATE_FAILED"), None
    )
    assert domain_failure is not None, f"no CREATE_FAILED event for DomainNameRes: {events_by_id.get('DomainNameRes')}"
    reason = domain_failure.get("ResourceStatusReason", "")
    # message varies: CloudFormation wraps AppSync's "Certificate is invalid." with that call's
    # Request ID, the handler's RequestToken and an SDK attempt count, none of which the check
    # creates or can predict.
    assert "certificate is invalid" in reason.lower(), f"expected the certificate-trust rejection, got: {reason}"

    # Positive control: an unrelated resource in the SAME stack did reach CREATE_COMPLETE
    # before the rollback undid it, so the account/credentials are otherwise healthy for
    # AppSync and the rejection above is specific to the certificate, not blanket denial.
    api_created = any(e["ResourceStatus"] == "CREATE_COMPLETE" for e in events_by_id.get("GraphQLApi", []))
    assert api_created, f"expected GraphQLApi to have reached CREATE_COMPLETE before rollback: {events_by_id.get('GraphQLApi')}"

    appsync = ctx.client("appsync")
    try:
        appsync.get_domain_name(domainName=domain_name)
        raise AssertionError(f"expected NotFoundException for {domain_name}, which was never actually created")
    except ClientError as exc:
        err = exc.response["Error"]
        assert (err.get("Code"), err.get("Message")) == ("NotFoundException", "Domain name not found"), err

    all_domains = appsync.list_domain_names().get("domainNameConfigs", [])
    assert domain_name not in {d["domainName"] for d in all_domains}


def _synthetic_domain(ctx) -> str:
    # CreateDomainName rejects RFC 2606 reserved documentation domains (example.com/.net/
    # .org, .test, .invalid, .localhost) with BadRequestException("Invalid domain name")
    # even though the string is otherwise well-formed. It never
    # resolves/validates ownership (only the certificate match matters), so an arbitrary
    # made-up ".com" name is accepted.
    label = ctx.unique_name("sim2real-domain-").lower().replace("_", "-")
    return f"{label}.com"


def _import_ca_signed_cert(ctx, domain_name: str) -> str:
    # CreateDomainName rejects a bare self-signed leaf (issuer == subject) with
    # BadRequestException("Certificate is invalid"). ACM's
    # ImportCertificate performs no public-trust-chain validation, so a throwaway
    # private root CA signing a domain leaf gives ACM a certificate it accepts
    # for import -- but CreateDomainName rejects a certificate signed by a private CA too,
    # with the same "Certificate is invalid".
    tmpdir = tempfile.mkdtemp(prefix="sim2real-appsync-cert-")
    ca_key_path = os.path.join(tmpdir, "ca-key.pem")
    ca_cert_path = os.path.join(tmpdir, "ca-cert.pem")
    leaf_key_path = os.path.join(tmpdir, "leaf-key.pem")
    leaf_csr_path = os.path.join(tmpdir, "leaf.csr")
    leaf_cert_path = os.path.join(tmpdir, "leaf-cert.pem")
    ext_path = os.path.join(tmpdir, "leaf-ext.cnf")
    try:
        subprocess.run(
            [
                "openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
                "-keyout", ca_key_path, "-out", ca_cert_path,
                "-days", "3650", "-subj", "/CN=sim2real-appsync-test-root-ca",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "openssl", "req", "-new", "-nodes", "-newkey", "rsa:2048",
                "-keyout", leaf_key_path, "-out", leaf_csr_path,
                "-subj", f"/CN={domain_name}",
            ],
            check=True,
            capture_output=True,
        )
        with open(ext_path, "w") as f:
            f.write(
                "basicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature,keyEncipherment\n"
                "extendedKeyUsage=serverAuth\n"
                f"subjectAltName=DNS:{domain_name}\n"
            )
        subprocess.run(
            [
                "openssl", "x509", "-req", "-in", leaf_csr_path,
                "-CA", ca_cert_path, "-CAkey", ca_key_path, "-CAcreateserial",
                "-out", leaf_cert_path, "-days", "30",
                "-extfile", ext_path,
            ],
            check=True,
            capture_output=True,
        )
        with open(leaf_cert_path, "rb") as f:
            cert_pem = f.read()
        with open(leaf_key_path, "rb") as f:
            key_pem = f.read()
        with open(ca_cert_path, "rb") as f:
            chain_pem = f.read()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    acm = _acm_client(ctx)
    cert_arn = acm.import_certificate(
        Certificate=cert_pem,
        PrivateKey=key_pem,
        CertificateChain=chain_pem,
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
    )["CertificateArn"]

    def _cleanup():
        # The refused DomainName can hold the certificate in use for a while; wait it out,
        # bounded, so a leaked certificate fails the teardown instead of passing silently.
        from botocore.exceptions import ClientError

        deadline = time.monotonic() + 300.0
        while True:
            try:
                acm.delete_certificate(CertificateArn=cert_arn)
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "ResourceNotFoundException":
                    return
                if code != "ResourceInUseException" or time.monotonic() >= deadline:
                    raise
            time.sleep(10.0)

    ctx.on_cleanup(_cleanup)
    return cert_arn


def _acm_client(ctx):
    # AppSync custom domains are served through an AppSync-managed CloudFront distribution, and
    # CloudFront only accepts ACM certificates from us-east-1, whatever the API's own Region.
    return ctx.client("acm", region="us-east-1")


def _domain_template() -> dict:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "ApiName": {"Type": "String"},
            "DomainNameParam": {"Type": "String"},
            "CertificateArnParam": {"Type": "String"},
        },
        "Resources": {
            "GraphQLApi": {
                "Type": "AWS::AppSync::GraphQLApi",
                "Properties": {"Name": {"Ref": "ApiName"}, "AuthenticationType": "API_KEY"},
            },
            "DomainNameRes": {
                "Type": "AWS::AppSync::DomainName",
                "Properties": {
                    "DomainName": {"Ref": "DomainNameParam"},
                    "CertificateArn": {"Ref": "CertificateArnParam"},
                },
            },
        },
    }


def _delete_stack(cfn, stack_name: str, max_attempts: int = 200) -> None:
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": max_attempts * 10 // 2}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
