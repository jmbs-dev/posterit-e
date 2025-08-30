import json

def lambda_handler(event, context):
    """
    Gestiona la verificación MFA y la liberación de un secreto.
    Asociado a POST /mfa/verify y GET /secrets/{secretId}/data
    """
    path = event.get('path', '')

    if '/mfa/verify' in path:
        # Lógica para POST /mfa/verify
        message = "MFA code verified successfully."
    elif '/data' in path:
        # Lógica para GET /secrets/{secretId}/data
        secret_id = event.get('pathParameters', {}).get('secretId')
        message = f"Secret data for {secret_id} released."
        # Aquí iría la lógica para devolver los datos del secreto
    else:
        return {"statusCode": 404, "body": "Not Found"}

    return {
        "statusCode": 200,
        "body": json.dumps({"message": message}),
    }