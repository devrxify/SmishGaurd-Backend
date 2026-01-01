import azure.functions as func
import logging
import json
import os
from azure.ai.contentsafety import ContentSafetyClient
from azure.ai.contentsafety.models import AnalyzeTextOptions
from azure.core.credentials import AzureKeyCredential

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

@app.route(route="AnalyzeText")
def AnalyzeText(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('SmishGuard: Received a request.')
    try:
        key = os.environ["CONTENT_SAFETY_KEY"]
        endpoint = os.environ["CONTENT_SAFETY_ENDPOINT"]
    except KeyError:
        return func.HttpResponse("Error: Missing AI Keys in settings.", status_code=500)
    try:
        req_body = req.get_json()
        sms_text = req_body.get('sms_text')
    except ValueError:
        return func.HttpResponse("Error: Invalid JSON.", status_code=400)

    if not sms_text:
        return func.HttpResponse("Error: 'sms_text' is missing.", status_code=400)
    try:
        client = ContentSafetyClient(endpoint, AzureKeyCredential(key))
        request = AnalyzeTextOptions(text=sms_text)
        response = client.analyze_text(request)
        risk_flag = False
        details = []

        if response.categories_analysis:
            for category in response.categories_analysis:
                if category.severity > 0:
                    risk_flag = True
                    details.append(f"{category.category}: Severity {category.severity}")
        result = {
            "sms_analyzed": sms_text,
            "is_suspicious": risk_flag,
            "risk_details": details,
            "status": "Scanned by Azure AI"
        }

        return func.HttpResponse(json.dumps(result), mimetype="application/json", status_code=200)

    except Exception as e:
        return func.HttpResponse(f"AI Analysis Failed: {str(e)}", status_code=500)