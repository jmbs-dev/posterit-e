import json

def lambda_handler(event, context):
    """
    Gestiona la activación de secretos.
    Asociado a GET /activation/{secretId} y POST /activation
    """
    http_method = event.get('httpMethod', 'GET')

    if http_method == 'POST':
        # Lógica para POST /activation
        message = "Activation process started."
    else:
        # Lógica para GET /activation/{secretId}
        secret_id = event.get('pathParameters', {}).get('secretId')
        message = f"Retrieving status for activation {secret_id}."

    return {
        "statusCode": 200,
        "body": json.dumps({"message": message}),
    }