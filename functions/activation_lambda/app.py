import os
import json
import boto3
import hmac
import uuid
import datetime
from botocore.exceptions import ClientError

dynamodb = boto3.resource('dynamodb')
CONFIG_SK = "CONFIG"
scheduler_client = boto3.client('scheduler')

def _get_secret_config(table_name, secret_id, projection=None):
    """Fetch the CONFIG item for a given secretId from DynamoDB, with optional projection."""
    table = dynamodb.Table(table_name)
    pk = f"SECRET#{secret_id}"
    try:
        kwargs = {"Key": {"PK": pk, "SK": CONFIG_SK}}
        if projection:
            kwargs["ProjectionExpression"] = projection
        response = table.get_item(**kwargs)
    except ClientError as e:
        raise Exception(f"DynamoDB error: {e}")
    return response.get("Item")

def _format_response(status_code, body_dict):
    return {
        "statusCode": status_code,
        "body": json.dumps(body_dict),
    }

def _unauthorized():
    return _format_response(401, {"message": "Unauthorized."})

def _conflict():
    return _format_response(409, {"message": "El proceso de recuperación para este secreto ya está activo o ha finalizado."})

def _bad_request(msg):
    return _format_response(400, {"message": msg})

def _method_not_allowed():
    return _format_response(405, {"message": "Method Not Allowed."})

def _internal_error(msg):
    return _format_response(500, {"message": msg})

def _update_process_status_and_token(table_name, secret_id, cancellation_token):
    table = dynamodb.Table(table_name)
    try:
        table.update_item(
            Key={"PK": f"SECRET#{secret_id}", "SK": CONFIG_SK},
            UpdateExpression="SET processStatus = :new_status, cancellation_token = :token",
            ConditionExpression="processStatus = :initial",
            ExpressionAttributeValues={
                ":new_status": "ACTIVATION_PENDING",
                ":initial": "INITIAL",
                ":token": cancellation_token
            }
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False
        raise
    return True

# TODO: Implementar un scheduler para enviar emails/SMS cada N cantidad de tiempo configurable.
def _send_activation_email(to_address, cancellation_token):
    ses_client = boto3.client('ses')
    sender = os.environ["SENDER_EMAIL_ADDRESS"]
    subject = "Alerta de Seguridad: Se ha iniciado la recuperación de tu secreto en Posterit-E"
    cancel_url = f"https://posterit-e.com/cancel?token={cancellation_token}"
    body = (
        f"Hola,\n\nSe ha iniciado un proceso de recuperación para tu secreto en Posterit-E. "
        f"Si NO has autorizado este proceso, puedes cancelarlo inmediatamente usando el siguiente enlace seguro:\n\n"
        f"{cancel_url}\n\n"
        f"Si reconoces esta acción, puedes ignorar este mensaje.\n\n"
        f"Atentamente,\nEl equipo de Posterit-E"
    )
    try:
        ses_client.send_email(
            Source=sender,
            Destination={"ToAddresses": [to_address]},
            Message={
                "Subject": {"Data": subject, "Charset": "UTF-8"},
                "Body": {"Text": {"Data": body, "Charset": "UTF-8"}}
            }
        )
    except ClientError as e:
        print(f"ERROR: Fallo al enviar email de activación al titular: {e}")

def get_salt_for_secret(event, table_name):
    """Handles the GET /activation/{secretId} use case: returns the saltCr for the given secretId."""
    secret_id = event.get("pathParameters", {}).get("secretId")
    if not secret_id:
        return _bad_request("Missing secretId in path.")
    item = _get_secret_config(table_name, secret_id, projection="saltCr")
    if not item or not item.get("saltCr"):
        return _unauthorized()
    return _format_response(200, {"saltCr": item["saltCr"]})

def _schedule_secret_release(secret_id, grace_period_seconds):
    """Helper to schedule the release of the secret using EventBridge Scheduler."""
    if not isinstance(grace_period_seconds, int):
        try:
            grace_period_seconds = int(grace_period_seconds)
        except Exception:
            raise ValueError("El atributo gracePeriodSeconds es inválido o no está presente.")
    now = datetime.datetime.utcnow()
    release_time = now + datetime.timedelta(seconds=grace_period_seconds)
    schedule_expression = f"at({release_time.strftime('%Y-%m-%dT%H:%M:%S')})"
    release_lambda_arn = os.environ["RELEASE_LAMBDA_ARN"]
    scheduler_role_arn = os.environ["SCHEDULER_ROLE_ARN"]
    schedule_name = f"posterit-e-release-{secret_id}"
    try:
        scheduler_client.create_schedule(
            Name=schedule_name,
            ScheduleExpression=schedule_expression,
            ActionAfterCompletion='DELETE',
            Target={
                "Arn": release_lambda_arn,
                "RoleArn": scheduler_role_arn,
                "Input": json.dumps({"secretId": secret_id})
            },
            FlexibleTimeWindow={"Mode": "OFF"}
        )
    except ClientError as e:
        print(f"ERROR: Fallo al programar la liberación del secreto: {e}")
        raise

def verify_and_activate_process(event, table_name):
    """Handles the POST /activation use case: verifies the hash and activates the recovery process."""
    try:
        body = json.loads(event.get("body", "{}"))
    except Exception:
        return _bad_request("Invalid JSON body.")

    secret_id = body.get("secretId")
    client_hash = body.get("clientHash")
    if not secret_id or not client_hash:
        return _bad_request("Missing secretId or clientHash in request body.")

    item = _get_secret_config(table_name, secret_id, projection="passwordHashCr,processStatus,titularAlertContact,gracePeriodSeconds")
    if not item or not item.get("passwordHashCr"):
        return _unauthorized()
    if item.get("processStatus") != "INITIAL":
        return _conflict()

    stored_hash = item["passwordHashCr"]
    if not hmac.compare_digest(str(client_hash), str(stored_hash)):
        return _unauthorized()

    # Token requerido para que el titular pueda cancelar el proceso
    cancellation_token = str(uuid.uuid4())
    if not _update_process_status_and_token(table_name, secret_id, cancellation_token):
        return _conflict()

    titular_email = item.get("titularAlertContact")
    if titular_email:
        _send_activation_email(titular_email, cancellation_token)
    else:
        print(f"WARNING: No se encontró el email del titular para el secreto {secret_id}.")

    # --- Programar liberación con EventBridge Scheduler ---
    grace_period = item.get("gracePeriodSeconds")
    try:
        _schedule_secret_release(secret_id, grace_period)
    except Exception as e:
        return _internal_error("No se pudo programar la liberación del secreto.")

    print(f"INFO: Proceso de activación iniciado para el secreto {secret_id}. Notificando al titular y programando liberación.")
    return _format_response(200, {"message": "Proceso de activación iniciado. El Titular ha sido notificado y el período de gracia ha comenzado."})

def lambda_handler(event, context):
    table_name = os.environ["DYNAMODB_TABLE_NAME"]
    http_method = event.get("httpMethod", "GET")

    if http_method == "GET":
        return get_salt_for_secret(event, table_name)
    elif http_method == "POST":
        return verify_and_activate_process(event, table_name)
    else:
        return _method_not_allowed()
