"""ca-arn-validation-precedes-resource-lookup."""
from __future__ import annotations

import uuid
from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "ca-arn-validation-precedes-resource-lookup"
GROUP = 'error-semantics'
SERVICES = ['acm-pca']


def _err(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it must raise."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("call succeeded; expected a ClientError")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Across five ARN-taking acm-pca operations, a malformed CA ARN is InvalidArnException and a
    well-formed ARN for a missing CA is ResourceNotFoundException: shape is validated before
    lookup, and callers' error classification depends on the two codes differing."""
    pca = ctx.client("acm-pca")
    account = ctx.client("sts").get_caller_identity()["Account"]

    # Malformed: the resource segment carries no id, so the ARN cannot denote a CA.
    malformed = f"arn:aws:acm-pca:{ctx.region}:{account}:certificate-authority"
    # Well-formed and syntactically complete, but never minted.
    missing = (
        f"arn:aws:acm-pca:{ctx.region}:{account}:certificate-authority/{uuid.uuid4()}"
    )

    # Every one of these five operations models BOTH InvalidArnException and
    # ResourceNotFoundException, so both branches are reachable for each.
    cases = [
        ("DescribeCertificateAuthority",
         lambda arn: pca.describe_certificate_authority(CertificateAuthorityArn=arn)),
        ("ListTags",
         lambda arn: pca.list_tags(CertificateAuthorityArn=arn)),
        ("ListPermissions",
         lambda arn: pca.list_permissions(CertificateAuthorityArn=arn)),
        ("GetPolicy",
         lambda arn: pca.get_policy(ResourceArn=arn)),
        ("DeletePolicy",
         lambda arn: pca.delete_policy(ResourceArn=arn)),
    ]

    for op_name, call in cases:
        bad, bad_msg = _err(lambda call=call: call(malformed))
        assert bad == "InvalidArnException", (
            f"{op_name} on a malformed CA ARN must be InvalidArnException, got {bad!r}; "
            f"a lookup-first implementation returns ResourceNotFoundException here"
        )
        assert bad_msg == "Not a valid arn.", (
            f"{op_name} malformed-ARN message: {bad_msg!r}"
        )
        gone, gone_msg = _err(lambda call=call: call(missing))
        assert gone == "ResourceNotFoundException", (
            f"{op_name} on a well-formed but never-minted CA ARN must be "
            f"ResourceNotFoundException, got {gone!r}"
        )
        assert gone_msg == "Could not find specified CA", (
            f"{op_name} missing-CA message: {gone_msg!r}"
        )
        # The discriminating assertion: the two stages must produce different codes.
        assert bad != gone, (
            f"{op_name} returned {bad!r} for both a malformed ARN and a missing CA; "
            f"ARN validation and resource lookup are not distinct stages"
        )

    # Control -- the same client, region and account resolve a well-formed read, so the
    # rejections above are decisions about the ARN and not a broken endpoint.
    live = pca.list_certificate_authorities(MaxResults=1)
    assert "CertificateAuthorities" in live, (
        f"ListCertificateAuthorities missing CertificateAuthorities: {live}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
