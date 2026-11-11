"""reject-domain-name-access-association-invalid-fails."""
from __future__ import annotations

CHECK = "reject-domain-name-access-association-invalid-fails"
GROUP = "error-semantics"
SERVICES = ["apigateway"]

from behavioral_harness import tags


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RejectDomainNameAccessAssociation rejects a malformed ARN pair with BadRequestException and
    a well-formed but nonexistent association and domain ARN pair with NotFoundException."""
    apigw = ctx.client("apigateway")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    code, message = _error(
        lambda: apigw.reject_domain_name_access_association(
            domainNameAccessAssociationArn="not-a-valid-arn",
            domainNameArn="also-not-a-valid-arn",
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException for a malformed ARN pair, got {code!r}"
    assert message == "Invalid domain name ARN specified.", f"unexpected message: {message!r}"

    fake_domain_arn = (
        f"arn:aws:apigateway:{ctx.region}:{account_id}:/domainnames/"
        f"{ctx.unique_name('sim2real-nx-domain-')}.example.com+nonexistent1"
    )
    fake_assoc_arn = (
        f"arn:aws:apigateway:{ctx.region}:{account_id}:/domainnameaccessassociations/"
        f"{ctx.unique_name('sim2real-nx-assoc-')}"
    )
    code, message = _error(
        lambda: apigw.reject_domain_name_access_association(
            domainNameAccessAssociationArn=fake_assoc_arn,
            domainNameArn=fake_domain_arn,
        )
    )
    assert code == "NotFoundException", (
        f"expected NotFoundException for a well-formed but nonexistent association/domain ARN "
        f"pair, got {code!r}"
    )
    assert message == (
        "This private custom domain name doesn't have any domain name access associations."
    ), f"unexpected message: {message!r}"

    # Neither rejected call may have created anything observable under this account.
    associations = apigw.get_domain_name_access_associations()["items"]
    assert all(item["domainNameArn"] != fake_domain_arn for item in associations), (
        f"a rejected RejectDomainNameAccessAssociation call must not create an association "
        f"visible under domainNameArn={fake_domain_arn!r}"
    )


def _error(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available and must not be
    reported as an error-code mismatch. RejectDomainNameAccessAssociation has a low account
    rate limit, so a TooManyRequestsException is retried with backoff before it is returned."""
    import time

    from botocore.exceptions import ClientError

    for attempt in range(6):
        try:
            result = fn()
        except ClientError as err:
            e = err.response.get("Error", {})
            if e.get("Code") == "TooManyRequestsException" and attempt < 5:
                time.sleep(5 * (attempt + 1))
                continue
            return e.get("Code"), e.get("Message")
        break
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
