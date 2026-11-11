"""negative-domain-configuration-invalid-certificate-blocked."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "negative-domain-configuration-invalid-certificate-blocked"
GROUP = "overly-permissive"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDomainConfiguration with certificate ARNs that match no ACM certificate fails with
    InvalidRequestException "Certificate <arn> does not exist.", and DescribeDomainConfiguration
    then fails with ResourceNotFoundException."""
    iot = ctx.client("iot")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region

    domain_name = ctx.unique_name("sim2real-domaincfg").replace("_", "-")
    fake_server_cert_arn = f"arn:aws:acm:{region}:{account_id}:certificate/{uuid.uuid4()}"
    fake_validation_cert_arn = f"arn:aws:acm:{region}:{account_id}:certificate/{uuid.uuid4()}"

    code, message = _error(
        lambda: iot.create_domain_configuration(
            domainConfigurationName=domain_name,
            domainName=f"{ctx.unique_name('s2r')}.example.com".replace("_", "-"),
            serverCertificateArns=[fake_server_cert_arn],
            validationCertificateArn=fake_validation_cert_arn,
            serviceType="DATA",
        )
    )
    assert code == "InvalidRequestException", code
    assert message == f"Certificate {fake_server_cert_arn} does not exist.", message

    not_found_code, not_found_message = _error(
        lambda: iot.describe_domain_configuration(domainConfigurationName=domain_name)
    )
    assert not_found_code == "ResourceNotFoundException", not_found_code
    assert not_found_message == (
        "Could not find domain configuration for given account ID and domain configuration name, "
        f"AccountId: {account_id}, DomainConfigurationName: {domain_name}"
    ), not_found_message


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
