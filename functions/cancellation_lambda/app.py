import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """
    Gestiona la cancelación de la custodia de un secreto.
    Asociado a POST /cancel
    """
    # Lógica para cancelar la custodia
    return {
        "statusCode": 200,
        "body": json.dumps({"message": "Secret custody successfully cancelled."}),
    }