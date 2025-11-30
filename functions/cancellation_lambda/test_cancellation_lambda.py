import json
import pytest
from unittest.mock import patch, MagicMock
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from functions.cancellation_lambda import app

@pytest.fixture(autouse=True)
def mock_env(monkeypatch):
    monkeypatch.setenv('DYNAMODB_TABLE_NAME', 'TestTable')
    monkeypatch.setenv('EVENTBRIDGE_ARN', 'TestBus')
    monkeypatch.setenv('SESIdentityArn', 'noreply@posterite.app')

# --- Happy Path ---
def test_cancel_success():
    event = {"body": json.dumps({"token": "tok-abc"})}
    token_item = {"PK": "SECRET#sec-123", "SK": "TOKEN#CANCEL", "tokenValue": "tok-abc"}
    config_item = {"processStatus": "ACTIVATION_PENDING", "titularAlertContact": "owner@example.com"}
    with patch.object(app, 'dynamodb_resource') as mock_dynamodb, \
         patch.object(app, 'dynamodb_client') as mock_ddb_client, \
         patch.object(app, 'scheduler_client') as mock_scheduler, \
         patch.object(app, 'ses_client') as mock_ses:
        table = MagicMock()
        mock_dynamodb.Table.return_value = table
        table.query.return_value = {"Items": [token_item]}
        table.get_item.return_value = {"Item": config_item}
        mock_ddb_client.transact_write_items.return_value = {}
        mock_scheduler.delete_schedule.return_value = {}
        mock_ses.send_email.return_value = {}
        response = app.lambda_handler(event, None)
        mock_ddb_client.transact_write_items.assert_called_once()
        mock_scheduler.delete_schedule.assert_called_once()
        mock_ses.send_email.assert_called_once()
        assert response['statusCode'] == 200
        assert "cancelado" in json.loads(response['body'])['message']

# --- Token Not Found ---
def test_cancel_token_not_found():
    event = {"body": json.dumps({"token": "tok-abc"})}
    with patch.object(app, 'dynamodb_resource') as mock_dynamodb:
        table = MagicMock()
        mock_dynamodb.Table.return_value = table
        table.query.return_value = {"Items": []}
        response = app.lambda_handler(event, None)
        assert response['statusCode'] == 401
        assert "Invalid or expired" in json.loads(response['body'])['message']

# --- Missing Token ---
def test_cancel_missing_token():
    event = {"body": json.dumps({})}
    response = app.lambda_handler(event, None)
    assert response['statusCode'] == 400
    assert "Missing cancellation token" in json.loads(response['body'])['message']

# --- Secret Not Found ---
def test_cancel_secret_not_found():
    event = {"body": json.dumps({"token": "tok-abc"})}
    token_item = {"PK": "SECRET#sec-123", "SK": "TOKEN#CANCEL", "tokenValue": "tok-abc"}
    with patch.object(app, 'dynamodb_resource') as mock_dynamodb:
        table = MagicMock()
        mock_dynamodb.Table.return_value = table
        table.query.return_value = {"Items": [token_item]}
        table.get_item.return_value = {}
        response = app.lambda_handler(event, None)
        assert response['statusCode'] == 404
        assert "Secret not found" in json.loads(response['body'])['message']

# --- Wrong State ---
def test_cancel_wrong_state():
    event = {"body": json.dumps({"token": "tok-abc"})}
    token_item = {"PK": "SECRET#sec-123", "SK": "TOKEN#CANCEL", "tokenValue": "tok-abc"}
    config_item = {"processStatus": "INITIAL", "titularAlertContact": "owner@example.com"}
    with patch.object(app, 'dynamodb_resource') as mock_dynamodb:
        table = MagicMock()
        mock_dynamodb.Table.return_value = table
        table.query.return_value = {"Items": [token_item]}
        table.get_item.return_value = {"Item": config_item}
        response = app.lambda_handler(event, None)
        assert response['statusCode'] == 409
        assert "cannot be cancelled" in json.loads(response['body'])['message']

# --- Transaction Conflict ---
def test_cancel_transaction_conflict():
    event = {"body": json.dumps({"token": "tok-abc"})}
    token_item = {"PK": "SECRET#sec-123", "SK": "TOKEN#CANCEL", "tokenValue": "tok-abc"}
    config_item = {"processStatus": "ACTIVATION_PENDING", "titularAlertContact": "owner@example.com"}
    with patch.object(app, 'dynamodb_resource') as mock_dynamodb, \
         patch.object(app, 'dynamodb_client') as mock_ddb_client:
        table = MagicMock()
        mock_dynamodb.Table.return_value = table
        table.query.return_value = {"Items": [token_item]}
        table.get_item.return_value = {"Item": config_item}
        err = MagicMock()
        err.response = {'Error': {'Code': 'ConditionalCheckFailedException'}}
        mock_ddb_client.transact_write_items.side_effect = err
        response = app.lambda_handler(event, None)
        assert response['statusCode'] == 409
        assert "already cancelled" in json.loads(response['body'])['message']

# --- Internal Error ---
def test_cancel_internal_error():
    event = {"body": json.dumps({"token": "tok-abc"})}
    with patch.object(app, 'dynamodb_resource') as mock_dynamodb:
        table = MagicMock()
        mock_dynamodb.Table.return_value = table
        table.query.side_effect = Exception("fail")
        response = app.lambda_handler(event, None)
        assert response['statusCode'] == 500
        assert "Internal server error" in json.loads(response['body'])['message']
