"""delete-client-certificate-in-use-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-client-certificate-in-use-rejected"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteClientCertificate while still referenced by a stage is rejected with Conflict."""
    apigw = ctx.client("apigateway")

    cert = apigw.generate_client_certificate(
        description=ctx.unique_name("sim2real-behav-cert-"),
        tags={"sim2real": CHECK},
    )
    cert_id = cert["clientCertificateId"]
    ctx.on_cleanup(lambda: _delete_cert_ignore_not_found(apigw, cert_id))

    api = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-apigw-"), tags={"sim2real": CHECK})
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK")
    deployment = apigw.create_deployment(restApiId=api_id)
    stage_name = "certstage"
    apigw.create_stage(
        restApiId=api_id,
        stageName=stage_name,
        deploymentId=deployment["id"],
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _delete_stage_ignore_not_found(apigw, api_id, stage_name))

    apigw.update_stage(
        restApiId=api_id,
        stageName=stage_name,
        patchOperations=[{"op": "replace", "path": "/clientCertificateId", "value": cert_id}],
    )
    stage = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    assert stage["clientCertificateId"] == cert_id, (
        f"expected the stage to report clientCertificateId={cert_id!r} before the rejection is "
        f"meaningful, got {stage.get('clientCertificateId')!r}"
    )

    # (a) break exactly one thing: try to delete the cert while a stage still references it.
    code, message = _error(lambda: apigw.delete_client_certificate(clientCertificateId=cert_id))
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == (
        f"Cannot delete client certificate. Certificate ID '{cert_id}', is referenced in stage {stage_name}."
    ), f"unexpected in-use message: {message!r}"

    # (b) effect absent: the certificate still exists.
    still_there = apigw.get_client_certificate(clientCertificateId=cert_id)
    assert still_there["clientCertificateId"] == cert_id, (
        f"the rejected delete must not have removed the certificate: expected "
        f"clientCertificateId={cert_id!r} to still be gettable, got {still_there!r}"
    )

    # (c) positive control: after the stage no longer references it, deletion succeeds.
    apigw.delete_stage(restApiId=api_id, stageName=stage_name)
    apigw.delete_client_certificate(clientCertificateId=cert_id)
    final_code, final_message = _error(lambda: apigw.get_client_certificate(clientCertificateId=cert_id))
    assert final_code == "NotFoundException", "certificate was not actually deleted"
    assert final_message == "Invalid client certificate id specified", f"unexpected not-found message: {final_message!r}"


def _error(fn):
    """Call fn(), which real AWS refuses; return the ClientError's (Code, Message).
    An unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("real AWS refuses this call, but it SUCCEEDED")


def _delete_cert_ignore_not_found(apigw, cert_id):
    try:
        apigw.delete_client_certificate(clientCertificateId=cert_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise


def _delete_stage_ignore_not_found(apigw, api_id, stage_name):
    try:
        apigw.delete_stage(restApiId=api_id, stageName=stage_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
