import base64
import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime

import boto3
from botocore.exceptions import ClientError

REQUIRED_FIELDS = [
    'encryptedSecret', 'encryptedDek', 'saltKek', 'saltCr',
    'passwordHashCr', 'beneficiaryContact', 'gracePeriodSeconds', 'titularAlertContact'
]
CONFIG_SK = "CONFIG"
ENCRYPTED_PAYLOAD_SK = "ENCRYPTED_PAYLOAD"

s3_client = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')

logger = logging.getLogger()
logger.setLevel(logging.INFO)

class ValidationException(ValueError):
    """Custom exception for request validation errors."""
    pass

def lambda_handler(event, context):
    """
        AWS Lambda Function: storeSecretLambda

        Description:
        This function serves as the secure entry point for storing a new secret in the Posterit-E system.
        It receives a pre-encrypted payload from the Titular's client, validates the request structure,
        and orchestrates the storage of cryptographic artifacts into Amazon S3 and DynamoDB.
        The design adheres to a Zero-Knowledge model, meaning the server never has access to
        plaintext secrets or the keys needed for decryption.

        S3 Object:
        - Stores the main encrypted secret as a single binary object. The object's body
        consists of the Initialization Vector (IV_Secreto) prepended to the ciphertext
        of the user's secret.

        DynamoDB Items (Single-Table Design):
        Two items are stored under the same Partition Key (PK) to group related data:
        - CONFIG Item (SK: 'CONFIG'): Stores all non-sensitive metadata required to manage
        the recovery lifecycle, such as the `processStatus`, TTL attributes (`gracePeriodExpiresAt`),
        and the materials for activation verification (`passwordHashCr`, `saltCr`).
        - ENCRYPTED_PAYLOAD Item (SK: 'ENCRYPTED_PAYLOAD'): Stores the cryptographic payload
        necessary for decryption, specifically the encrypted Data Encryption Key (`encryptedDek`)
        and its corresponding salt (`saltKek`).
    """
    try:
        logger.info("Request received for storing secret.")
        table_name = os.environ['DYNAMODB_TABLE_NAME']
        bucket_name = os.environ['S3_BUCKET_NAME']
        logger.info(f"Using DynamoDB table: {table_name} and S3 bucket: {bucket_name}")
        body = _parse_and_validate_body(event)
        logger.info("Request body validated. Required fields present.")
        metadata = _generate_server_side_metadata(body['gracePeriodSeconds'])
        logger.info(f"Generated metadata for secretId: {metadata['secret_id']}")
        _upload_secret_to_s3(bucket_name, metadata['s3_object_key'], body['encryptedSecret'])
        logger.info(f"Encrypted secret uploaded to S3 with key: {metadata['s3_object_key']}")
        config_item, payload_item = _prepare_dynamodb_items(body, metadata)
        logger.info(f"Prepared DynamoDB items for secretId: {metadata['secret_id']}")
        dynamodb.meta.client.transact_write_items(
            TransactItems=[
                {'Put': {'TableName': table_name, 'Item': config_item}},
                {'Put': {'TableName': table_name, 'Item': payload_item}}
            ]
        )
        logger.info(f"DynamoDB transaction completed for secretId: {metadata['secret_id']}")
        return _format_response(201, {'message': 'Secret stored successfully.', 'secretId': metadata['secret_id']})
    except ValidationException as e:
        logger.warning(f"Validation error: {str(e)}")
        return _format_response(400, {'error': 'Invalid Request', 'details': str(e)})
    except ClientError as e:
        logger.error(f"AWS ClientError ({e.response['Error'].get('Code')}): {e}")
        return _format_response(500, {'error': 'Server Error', 'details': 'A service communication error occurred.'})
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return _format_response(500, {'error': 'Internal Server Error', 'details': 'An unexpected error occurred.'})

def _parse_and_validate_body(event):
    """Parses and validates the incoming request body."""
    raw_body = event.get('body')
    if raw_body is None:
        raw_body = '{}'
    body = json.loads(raw_body)
    if not body:
        raise ValidationException("Request body cannot be empty.")
    for field in REQUIRED_FIELDS:
        if field not in body:
            raise ValidationException(f"Required field '{field}' is missing.")
    return body

def _generate_server_side_metadata(grace_period_seconds):
    """Generates server-side metadata like unique IDs and timestamps."""
    secret_id = f"sec-{uuid.uuid4()}"
    now_epoch = int(time.time())
    return {
        'secret_id': secret_id,
        's3_object_key': secret_id,
        'created_at_iso': datetime.utcnow().isoformat(),
        'grace_period_expires_at': now_epoch + int(grace_period_seconds)
    }

def _upload_secret_to_s3(bucket_name, key, encrypted_secret_base64):
    """Decodes the Base64 secret and uploads it to S3."""
    try:
        encrypted_secret_bytes = base64.b64decode(encrypted_secret_base64)
        s3_client.put_object(Bucket=bucket_name, Key=key, Body=encrypted_secret_bytes)
    except (TypeError, base64.binascii.Error):
        raise ValidationException("Field 'encryptedSecret' is not a valid Base64 string.")

def _prepare_dynamodb_items(body, metadata):
    """Prepares the CONFIG and ENCRYPTED_PAYLOAD items for DynamoDB."""
    pk = f"SECRET#{metadata['secret_id']}"

    config_item = {
        'PK': pk,
        'SK': CONFIG_SK,
        'secretId': metadata['secret_id'],
        'beneficiaryMfaContact': body['beneficiaryContact'],
        'titularAlertContact': body['titularAlertContact'],
        'processStatus': 'INITIAL',
        'gracePeriodSeconds': int(body['gracePeriodSeconds']),
        'gracePeriodExpiresAt': metadata['grace_period_expires_at'],
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
