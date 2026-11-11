"""put-signing-profile-creates-active-profile."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-signing-profile-creates-active-profile"
GROUP = "control-plane"
SERVICES = ["signer"]

LAMBDA_PLATFORM = "AWSLambda-SHA384-ECDSA"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutSigningProfile creates a new profile that is immediately Active and fully described."""
    signer = ctx.client("signer")
    name = _profile_name(ctx, "create")
    ctx.on_cleanup(lambda: _cancel_quietly(signer, name))

    put_resp = signer.put_signing_profile(profileName=name, platformId=LAMBDA_PLATFORM)
    assert put_resp["arn"], f"expected a non-empty profile arn, got {put_resp.get('arn')!r}"
    assert len(put_resp["profileVersion"]) == 10, (
        f"expected a 10-character profileVersion (fixed by the signer#ProfileVersion shape), "
        f"got {put_resp['profileVersion']!r}"
    )

    desc = signer.get_signing_profile(profileName=name)
    assert desc["profileName"] == name, f"expected profileName {name!r}, got {desc['profileName']!r}"
    assert desc["platformId"] == LAMBDA_PLATFORM, (
        f"expected platformId {LAMBDA_PLATFORM!r}, got {desc['platformId']!r}"
    )
    assert desc["status"] == "Active", f"expected status 'Active', got {desc['status']!r}"
    assert desc["profileVersion"] == put_resp["profileVersion"], (
        f"expected profileVersion {put_resp['profileVersion']!r} from the independent read, "
        f"got {desc['profileVersion']!r}"
    )
    assert desc["profileVersionArn"] == put_resp["profileVersionArn"], (
        f"expected profileVersionArn {put_resp['profileVersionArn']!r}, got {desc['profileVersionArn']!r}"
    )
    assert desc["arn"] == put_resp["arn"], f"expected arn {put_resp['arn']!r}, got {desc['arn']!r}"


def _profile_name(ctx, kind: str) -> str:
    return ctx.unique_name(f"sim2real-signer-{kind}-").replace("-", "_")


def _cancel_quietly(signer, profile_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        signer.cancel_signing_profile(profileName=profile_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
