"""codesigning-config-list-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "codesigning-config-list-roundtrip"
GROUP = "state-machine"
SERVICES = ["lambda"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly created CSC appears in ListCodeSigningConfigs and disappears after delete."""
    lam = ctx.client("lambda")
    profile_arn = _signing_profile_version_arn(ctx)

    created = lam.create_code_signing_config(
        AllowedPublishers={"SigningProfileVersionArns": [profile_arn]},
        Description="sim2real list roundtrip",
        Tags={"sim2real:managed": "true"},
    )["CodeSigningConfig"]
    arn = created["CodeSigningConfigArn"]
    ctx.on_cleanup(lambda: _delete_csc_ignore(lam, arn))

    assert _arn_in_list(lam, arn), "newly created CSC not found in ListCodeSigningConfigs"

    lam.delete_code_signing_config(CodeSigningConfigArn=arn)

    assert not _arn_in_list(lam, arn), "deleted CSC still present in ListCodeSigningConfigs"

    code, message = _client_error(lambda: lam.get_code_signing_config(CodeSigningConfigArn=arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading a deleted CSC, got {code!r}"
    )
    assert message == _csc_not_found_message(arn), (
        f"expected message {_csc_not_found_message(arn)!r} reading a deleted CSC, got {message!r}"
    )


def _signing_profile_version_arn(ctx) -> str:
    """Create this check's own Signer profile (cancelled at cleanup) and return its version ARN."""
    import uuid

    signer = ctx.client("signer")
    name = "sim2realbehav" + uuid.uuid4().hex[:16]
    prof = signer.put_signing_profile(
        profileName=name,
        platformId="AWSLambda-SHA384-ECDSA",
        tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: signer.cancel_signing_profile(profileName=name))
    return prof["profileVersionArn"]


def _arn_in_list(lam, arn: str) -> bool:
    marker = None
    while True:
        kwargs = {"MaxItems": 50}
        if marker:
            kwargs["Marker"] = marker
        resp = lam.list_code_signing_configs(**kwargs)
        for csc in resp.get("CodeSigningConfigs", []):
            if csc["CodeSigningConfigArn"] == arn:
                return True
        marker = resp.get("NextMarker")
        if not marker:
            return False


def _delete_csc_ignore(lam, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        lam.delete_code_signing_config(CodeSigningConfigArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "CodeSigningConfigNotFoundException",
            "ResourceNotFoundException",
        ):
            raise


def _client_error(call):
    """Run a call that MUST be refused and return its (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = call()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _csc_not_found_message(csc_arn: str) -> str:
    return f"The Lambda code signing configuration {csc_arn} can not be found."


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
