"""concurrent-create-domain-name-access-association-duplicate-race."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-create-domain-name-access-association-duplicate-race"
GROUP = "concurrency"
SERVICES = ["apigateway"]

# Racing identical CreateDomainNameAccessAssociation calls against a well-formed but nonexistent
# domain/VPC endpoint pair: every racer is rejected and no association is left behind.


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateDomainNameAccessAssociation calls for the same nonexistent domain/source pair are
    all rejected (BadRequestException, or TooManyRequestsException when throttled), none succeeds, and
    no association is left behind."""
    apigw = ctx.client("apigateway")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # Positive control: the read side of this same API family is not a blanket-failing stub.
    control = apigw.get_domain_name_access_associations()
    assert isinstance(control["items"], list), (
        f"GetDomainNameAccessAssociations did not return a well-formed items list: {control!r}"
    )

    fake_domain_token = ctx.unique_name("sim2real-dnaa-race")
    fake_domain_arn = (
        f"arn:aws:apigateway:{ctx.region}:{account_id}:/domainnames/"
        f"{fake_domain_token}.example.com+00000000"
    )
    fake_vpce_id = "vpce-" + "0" * 17

    num_racers = 6

    def _race(_: int):
        return _error(
            lambda: apigw.create_domain_name_access_association(
                domainNameArn=fake_domain_arn,
                accessAssociationSourceType="VPCE",
                accessAssociationSource=fake_vpce_id,
            )
        )

    with ThreadPoolExecutor(max_workers=num_racers) as pool:
        outcomes = list(pool.map(_race, range(num_racers)))
    codes = [code for code, _ in outcomes]

    assert len(codes) == num_racers, f"expected {num_racers} racer outcomes, got {len(codes)}: {codes}"
    # Real AWS applies a control-plane throttle to this operation: firing num_racers identical
    # calls at once produces a mix of TooManyRequestsException (throttled before validation) and
    # BadRequestException (fully validated and rejected). A success or any other code fails.
    allowed_codes = {"BadRequestException", "TooManyRequestsException"}
    assert all(code in allowed_codes for code in codes), (
        f"every racer against a nonexistent domainNameArn/VPCE pair must be deterministically "
        f"rejected -- either fully validated (BadRequestException) or throttled "
        f"(TooManyRequestsException), never a success or any other code: {codes}"
    )
    assert "BadRequestException" in codes, (
        f"no racer reached full validation -- every racer was throttled, which cannot be told "
        f"apart from a blanket-denying stub: {codes}"
    )
    expected_messages = {"BadRequestException": "Domain not found", "TooManyRequestsException": "Too Many Requests"}
    for code, message in outcomes:
        assert message == expected_messages[code], f"{code}: {message!r}"

    after = apigw.get_domain_name_access_associations()
    leaked = [
        item
        for item in after["items"]
        if item.get("accessAssociationSource") == fake_vpce_id
        or item.get("domainNameArn") == fake_domain_arn
    ]
    assert not leaked, (
        f"a ghost/partial association for the rejected racers was left behind: {leaked}"
    )


def _error(fn):
    """The (code, message) of the ClientError fn raises, or ("SUCCEEDED", None) when it succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return "SUCCEEDED", None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
