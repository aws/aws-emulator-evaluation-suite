"""client-certificate-delete-while-assigned-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "client-certificate-delete-while-assigned-rejected"
GROUP = "visibility-timeout-ttl"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteClientCertificate is rejected with BadRequestException while a stage uses the
    certificate, which stays intact; once the stage drops it, the identical call succeeds
    and a read confirms the certificate is gone."""
    apigw = ctx.client("apigateway")

    cert_id = apigw.generate_client_certificate(
        description=ctx.unique_name("sim2real-cc-rej-"), tags={"sim2real": CHECK}
    )["clientCertificateId"]
    ctx.on_cleanup(lambda: _best_effort_delete(apigw, cert_id))

    rest_api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-cc-rej-api-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=rest_api_id))
    root_id = apigw.get_resources(restApiId=rest_api_id)["items"][0]["id"]
    apigw.put_method(restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    deployment_id = apigw.create_deployment(restApiId=rest_api_id)["id"]
    stage_name = "test"
    apigw.create_stage(restApiId=rest_api_id, stageName=stage_name, deploymentId=deployment_id)
    apigw.update_stage(
        restApiId=rest_api_id,
        stageName=stage_name,
        patchOperations=[{"op": "replace", "path": "/clientCertificateId", "value": cert_id}],
    )
    stage = apigw.get_stage(restApiId=rest_api_id, stageName=stage_name)
    assert stage["clientCertificateId"] == cert_id, (
        f"stage must be observably assigned the certificate before anything is concluded from "
        f"blocking its deletion; got {stage.get('clientCertificateId')!r}"
    )

    code, message = _error(lambda: apigw.delete_client_certificate(clientCertificateId=cert_id))
    assert code == "BadRequestException", f"expected BadRequestException while assigned, got {code}"
    expected = f"Cannot delete client certificate. Certificate ID '{cert_id}', is referenced in stage {stage_name}."
    assert message == expected, f"expected {expected!r}, got {message!r}"
    still_there = apigw.get_client_certificate(clientCertificateId=cert_id)
    assert still_there["clientCertificateId"] == cert_id, (
        f"certificate must still exist after the rejected delete; got {still_there!r}"
    )

    apigw.update_stage(
        restApiId=rest_api_id,
        stageName=stage_name,
        patchOperations=[{"op": "replace", "path": "/clientCertificateId", "value": ""}],
    )
    stage_after = apigw.get_stage(restApiId=rest_api_id, stageName=stage_name)
    assert not stage_after.get("clientCertificateId"), (
        f"stage must no longer reference the certificate before the retry; got "
        f"{stage_after.get('clientCertificateId')!r}"
    )
    apigw.delete_client_certificate(clientCertificateId=cert_id)
    final_code, message = _error(lambda: apigw.get_client_certificate(clientCertificateId=cert_id))
    assert final_code == "NotFoundException", (
        f"expected the certificate to be actually deleted once unassigned, got error code {final_code}"
    )
    assert message == "Invalid client certificate id specified", f"unexpected message {message!r}"



def _best_effort_delete(apigw, cert_id: str) -> None:
    try:
        apigw.delete_client_certificate(clientCertificateId=cert_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _error(fn):
    """The captured AWS (error code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

