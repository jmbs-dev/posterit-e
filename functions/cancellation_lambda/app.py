import os
import json
import logging
import boto3
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key

logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = boto3.resource('dynamodb')
scheduler_client = boto3.client('scheduler')

def get_cors_headers(event):
    return {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Allow-Methods": "POST,OPTIONS,GET"
    }

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Methods": "POST,OPTIONS,GET"
}

def lambda_handler(event, context):
    """
    Handles the cancellation of secret custody.
    Triggered by POST /cancel
    """
    cors_headers = get_cors_headers(event)
    try:
        body = json.loads(event.get("body", "{}"))
        cancellation_token = body.get("cancellation_token")
    except Exception:
        logger.warning("Malformed request body.")
        return _bad_request("Malformed request body.", cors_headers)
    if not cancellation_token:
        logger.warning("Missing cancellation_token in request.")
        return _bad_request("Missing cancellation_token in request.", cors_headers)

    table_name = os.environ["DYNAMODB_TABLE_NAME"]
    gsi_name = os.environ.get("CANCELLATION_GSI_NAME", "CancellationIndex")
    table = dynamodb.Table(table_name)

    try:
        response = table.query(
            IndexName=gsi_name,
            KeyConditionExpression=Key('cancellation_token').eq(cancellation_token)
        )
        items = response.get('Items', [])
    except ClientError as e:
        logger.error(f"Error querying DynamoDB: {e}")
        _notify_owner_cancellation_failed(None, None, None, error="DynamoDB query error")
        return _internal_error("Database query error.", cors_headers)

    if not items:
        logger.warning("Cancellation token not found or invalid.")
        return _unauthorized(cors_headers)

    item = items[0]
    pk = item['PK']
    sk = item['SK']
    secret_id = pk.replace('SECRET#', '')
    titular_email = item.get("titularAlertContact")

    try:
        table.update_item(
            Key={"PK": pk, "SK": sk},
            UpdateExpression="SET processStatus = :cancelled REMOVE cancellation_token, gracePeriodExpiresAt",
            ConditionExpression="processStatus = :pending",
            ExpressionAttributeValues={":cancelled": "CANCELLED", ":pending": "ACTIVATION_PENDING"}
        )
        logger.info(f"Secret {secret_id} successfully cancelled.")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            logger.warning(f"Could not cancel secret {secret_id}: invalid state.")
            _notify_owner_cancellation_failed(titular_email, secret_id, reason="invalid state")
            return _unauthorized(cors_headers)
        logger.error(f"Error updating DynamoDB state: {e}")
        _notify_owner_cancellation_failed(titular_email, secret_id, reason="DynamoDB update error")
        return _internal_error("Error updating state.", cors_headers)

    schedule_name = f"posterit-e-release-{secret_id}"
    try:
        scheduler_client.delete_schedule(Name=schedule_name)
        logger.info(f"Scheduled event {schedule_name} deleted.")
    except ClientError as e:
        logger.error(f"Error deleting scheduled event: {e}")
        _notify_owner_cancellation_failed(titular_email, secret_id, reason="schedule deletion failed")
        return _internal_error("Failed to delete scheduled event. The secret may still be released. Owner has been alerted.", cors_headers)

    if titular_email:
        _send_cancellation_email(titular_email, secret_id)
    return {
        "statusCode": 200,
        "headers": cors_headers,
        "body": json.dumps({"message": "El proceso de recuperación ha sido cancelado exitosamente."}),
    }

def _bad_request(msg, cors_headers):
    return {"statusCode": 400, "headers": cors_headers, "body": json.dumps({"message": msg})}

def _unauthorized(cors_headers):
    return {
        "statusCode": 401,
        "headers": cors_headers,
        "body": json.dumps({
            "message": "El token de cancelación es inválido, ha expirado o ya fue utilizado."
        })
    }

def _internal_error(msg, cors_headers):
    return {"statusCode": 500, "headers": cors_headers, "body": json.dumps({"message": msg})}

def _send_cancellation_email(to_address, secret_id):
    ses_client = boto3.client('ses')
    sender = os.getenv("SENDER_EMAIL_ADDRESS")
    subject = "Proceso de recuperación cancelado en Posterit-E"
    body = (
        f"Hola,\n\nEl proceso de recuperación para tu secreto (ID: {secret_id}) ha sido cancelado exitosamente.\n\n"
        f"Si no realizaste esta acción, por favor contacta al soporte de Posterit-E.\n\n"
        f"Saludos,\nEl equipo de Posterit-E"
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
        logger.info(f"Cancellation email sent to {to_address}")
    except ClientError as e:
        logger.error(f"Error sending cancellation email: {e}")

def _notify_owner_cancellation_failed(to_address, secret_id, reason=None, error=None):
    if not to_address:
        logger.warning("No titular email to notify about cancellation failure.")
        return
    ses_client = boto3.client('ses')
    sender = os.getenv("SENDER_EMAIL_ADDRESS")
    subject = "No se pudo cancelar el proceso de recuperación en Posterit-E"
    body = (
        f"Hola,\n\nNo se pudo cancelar el proceso de recuperación para tu secreto"
        + (f" (ID: {secret_id})" if secret_id else "") + ".\n\n"
        "Por favor, contacta al soporte de Posterit-E para obtener ayuda.\n\n"
        "Si no reconoces esta acción, es importante que informes al soporte lo antes posible.\n\n"
        "Saludos,\nEl equipo de Posterit-E"
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
        logger.info(f"Error notification email sent to {to_address}")
    except ClientError as e:
        logger.error(f"Error sending error notification email: {e}")
