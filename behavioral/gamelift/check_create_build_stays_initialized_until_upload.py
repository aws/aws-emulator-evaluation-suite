"""create-build-stays-initialized-until-upload."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-build-stays-initialized-until-upload"
GROUP = "state"
SERVICES = ["gamelift"]


def _upload_creds(creds):
    return {
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    }


def _s3_for_upload_credentials(ctx, creds):
    """An S3 client signing AS the temporary principal GameLift minted for this build's upload.

    GameLift's own build bucket is not reachable by the account's own client -- only the
    credentials this check is testing can reach it, so this is the only way to prove the location
    is real and usable rather than just a response shape.
    """
    return ctx.client("s3", creds=_upload_creds(creds))


def _error(fn):
    """The (code, message) of the ClientError fn() raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateBuild without content leaves the build INITIALIZED with SizeOnDisk 0; RequestUploadCredentials returns
    its StorageLocation with credentials that can PutObject there but get AccessDenied and its exact message on
    GetObject, and the build is still INITIALIZED after the upload.
    """
    gl = ctx.client("gamelift")
    name = ctx.unique_name("sim2real-build-")

    created = gl.create_build(
        Name=name,
        Version="1.0",
        OperatingSystem="AMAZON_LINUX_2023",
        ServerSdkVersion="5.2.0",
        Tags=[{"Key": "env", "Value": "sim2real"}, {"Key": "owner", "Value": "behavioral"}],
    )
    build = created["Build"]
    build_id = build["BuildId"]
    ctx.on_cleanup(lambda: gl.delete_build(BuildId=build_id))

    assert build["Status"] == "INITIALIZED", (
        f"CreateBuild without ZipFile/StorageLocation must start INITIALIZED; got {build['Status']!r}"
    )
    assert build["SizeOnDisk"] == 0, (
        f"an upload-pending build must report SizeOnDisk 0; got {build['SizeOnDisk']!r}"
    )
    assert "StorageLocation" in created, (
        f"CreateBuild must hand back a StorageLocation to upload to; got keys {sorted(created)!r}"
    )
    bucket = created["StorageLocation"]["Bucket"]
    key = created["StorageLocation"]["Key"]
    assert bucket, f"StorageLocation.Bucket must be non-empty; got {bucket!r}"

    # Describing again immediately after creation: still INITIALIZED, no auto-advance.
    described = gl.describe_build(BuildId=build_id)["Build"]
    assert described["Status"] == "INITIALIZED", (
        f"an immediate re-describe with no upload must still report INITIALIZED; "
        f"got {described['Status']!r}"
    )

    creds = gl.request_upload_credentials(BuildId=build_id)
    assert creds["StorageLocation"]["Bucket"] == bucket, (
        f"RequestUploadCredentials must target the same bucket CreateBuild minted "
        f"({bucket!r}); got {creds['StorageLocation']['Bucket']!r}"
    )
    assert creds["StorageLocation"]["Key"] == key, (
        f"RequestUploadCredentials must target the same key CreateBuild minted "
        f"({key!r}); got {creds['StorageLocation']['Key']!r}"
    )
    assert "AccessKeyId" in creds["UploadCredentials"], (
        f"RequestUploadCredentials must mint usable credentials; got keys "
        f"{sorted(creds['UploadCredentials'])!r}"
    )

    # Write real bytes with the minted credentials to the exact location RequestUploadCredentials named. The
    # minted role is scoped to upload only: the credentials that can PutObject to this key are refused GetObject
    # on it with AccessDenied.
    payload = b"sim2real-gamelift-build-payload"
    s3 = _s3_for_upload_credentials(ctx, creds["UploadCredentials"])
    put_response = s3.put_object(Bucket=bucket, Key=key, Body=payload)
    assert put_response["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"the minted credentials must be able to write to the exact location "
        f"RequestUploadCredentials named; PutObject returned "
        f"{put_response['ResponseMetadata']['HTTPStatusCode']!r}"
    )
    read_back_denied, denied_message = _error(lambda: s3.get_object(Bucket=bucket, Key=key))
    assert read_back_denied == "AccessDenied", (
        f"RequestUploadCredentials mints upload-only access -- a GetObject with the same "
        f"credentials that just wrote the object must be refused with exactly AccessDenied; "
        f"got {read_back_denied!r}"
    )
    upload_principal = ctx.client("sts", creds=_upload_creds(creds["UploadCredentials"]))
    principal_arn = upload_principal.get_caller_identity()["Arn"]
    expected_message = (
        f"User: {principal_arn} is not authorized to perform: s3:GetObject on resource: "
        f'"arn:aws:s3:::{bucket}/{key}" because no session policy allows the s3:GetObject action'
    )
    assert denied_message == expected_message, (
        f"expected S3's exact session-policy denial {expected_message!r}; got {denied_message!r}"
    )

    # Real bytes landing at the upload location does not itself flip the build to READY --
    # GameLift's own validation of the upload is what does that, not the mere presence of an
    # object at the key.
    after_upload = gl.describe_build(BuildId=build_id)["Build"]
    assert after_upload["Status"] == "INITIALIZED", (
        f"landing bytes at the upload location must not by itself advance the build past "
        f"INITIALIZED; got {after_upload['Status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
