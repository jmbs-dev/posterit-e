import base64
import json
import logging
import os
import uuid
from datetime import datetime, timezone
import binascii
from decimal import Decimal

import boto3
from botocore.exceptions import ClientError
from boto3.dynamodb.types import TypeSerializer

REQUIRED_FIELDS = [
    'encryptedSecret', 'encryptedDek', 'saltKek', 'saltCr',
    'passwordHashCr', 'beneficiaryContact', 'gracePeriodSeconds', 'titularAlertContact'
]
CONFIG_SK = "CONFIG"
ENCRYPTED_PAYLOAD_SK = "ENCRYPTED_PAYLOAD"

s3_client = boto3.client('s3')
ddb_client = boto3.client('dynamodb')
serializer = TypeSerializer()

logger = logging.getLogger()
logger.setLevel(logging.INFO)

class ValidationException(ValueError):
    """Custom exception for request validation errors."""
    pass

def lambda_handler(event, context):
    try:
        logger.info("Request received for storing secret.")
        table_name = os.environ['DYNAMODB_TABLE_NAME']
        bucket_name = os.environ['S3_BUCKET_NAME']

        body = _parse_and_validate_body(event)

        metadata = _generate_server_side_metadata(body['gracePeriodSeconds'])

        _upload_secret_to_s3(bucket_name, metadata['s3_object_key'], body['encryptedSecret'])

        config_item, payload_item = _prepare_dynamodb_items(body, metadata)
        cancellation_token, cancel_token_item = create_cancellation_token_item(metadata['secret_id'])

        config_serialized = _serialize_item(config_item)
        payload_serialized = _serialize_item(payload_item)
        token_serialized = _serialize_item(cancel_token_item)

        logger.info(f"Writing transaction for secretId: {metadata['secret_id']}")

        ddb_client.transact_write_items(
            TransactItems=[
                {'Put': {'TableName': table_name, 'Item': config_serialized}},
                {'Put': {'TableName': table_name, 'Item': payload_serialized}},
                {'Put': {'TableName': table_name, 'Item': token_serialized}}
            ]
        )

        logger.info("Transaction completed successfully.")
        return _format_response(201, {
            'message': 'Secret stored successfully.',
            'secretId': metadata['secret_id'],
            'cancellationToken': cancellation_token
        })

    except ValidationException as e:
        logger.warning(f"Validation error: {str(e)}")
        return _format_response(400, {'error': 'Invalid Request', 'details': str(e)})
    except ClientError as e:
        logger.error(f"AWS ClientError: {e}")
        return _format_response(500, {'error': 'Server Error', 'details': str(e)})
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return _format_response(500, {'error': 'Internal Server Error'})

def _parse_and_validate_body(event):
    raw_body = event.get('body') or '{}'
    body = json.loads(raw_body)
    if not body:
        raise ValidationException("Request body cannot be empty.")
    for field in REQUIRED_FIELDS:
        if field not in body:
            raise ValidationException(f"Required field '{field}' is missing.")
    return body

def _generate_server_side_metadata(grace_period_seconds):
    secret_id = f"sec-{uuid.uuid4()}"
    return {
        'secret_id': secret_id,
        's3_object_key': secret_id,
        'created_at_iso': datetime.now(timezone.utc).isoformat(),
        'gracePeriodSeconds': int(grace_period_seconds)
    }

def _upload_secret_to_s3(bucket_name, key, encrypted_secret_base64):
    try:
        encrypted_secret_bytes = base64.b64decode(encrypted_secret_base64)
        s3_client.put_object(Bucket=bucket_name, Key=key, Body=encrypted_secret_bytes)
    except (TypeError, binascii.Error):
        raise ValidationException("Field 'encryptedSecret' is not a valid Base64 string.")

def _prepare_dynamodb_items(body, metadata):
    pk = f"SECRET#{metadata['secret_id']}"

    config_item = {
        'PK': pk,
        'SK': CONFIG_SK,
        'secretId': metadata['secret_id'],
        'beneficiaryMfaContact': body['beneficiaryContact'],
        'titularAlertContact': body['titularAlertContact'],
        'processStatus': 'CREATED',
        'gracePeriodSeconds': metadata['gracePeriodSeconds'],
        'passwordHashCr': body['passwordHashCr'],
        'saltCr': body['saltCr'],
        'createdAt': metadata['created_at_iso']
    }

    encrypted_payload_item = {
        'PK': pk,
        'SK': ENCRYPTED_PAYLOAD_SK,
        's3ObjectKey': metadata['s3_object_key'],
        'encryptedDek': body['encryptedDek'],
        'saltKek': body['saltKek']
    }
    return config_item, encrypted_payload_item

def create_cancellation_token_item(secret_id):
    """Returns the token and the item dict (not yet serialized)."""
    pk = f"SECRET#{secret_id}"
    token = str(uuid.uuid4())
    cancel_token_item = {
        'PK': pk,
        'SK': 'TOKEN#CANCEL',
        'tokenValue': token,
        'tokenType': 'CANCELLATION'
    }
    return token, cancel_token_item

def _serialize_item(item):
    """
    Serializes a Python dictionary to DynamoDB format using TypeSerializer.
    Handles Floats -> Decimal and removes empty Strings.
    """
    clean_item = {}
    for k, v in item.items():
        if isinstance(v, str) and v == "":
            continue
        if isinstance(v, float):
            clean_item[k] = serializer.serialize(Decimal(str(v)))
        else:
            clean_item[k] = serializer.serialize(v)
    return clean_item

def _format_response(status_code, body):
    return {
        'statusCode': status_code,
        'headers': {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
            'Access-Control-Allow-Methods': 'POST,OPTIONS'
        },
        'body': json.dumps(body)
    }

