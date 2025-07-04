
import os
import logging
import requests
from azure.identity import ClientSecretCredential
from azure.keyvault.secrets import SecretClient
from msgraph.core import GraphClient
import azure.functions as func

def get_env_code():
    fa_name = os.environ.get("AZURE_FUNCTION_APP_NAME", "")
    rg_name = os.environ.get("AZURE_RESOURCE_GROUP", "")
    for source in [fa_name, rg_name]:
        parts = source.split("-")
        if len(parts) >= 3 and parts[0] == "dqe3":
            return parts[1]
    return "d"

def main(mytimer: func.TimerRequest) -> None:
    logging.info("Databricks sync function triggered.")

    env_code = get_env_code()
    kv_url = f"https://dqe3-{env_code}-kv.vault.azure.net"

    # Use managed identity to read client ID and password from Key Vault
    credential = DefaultAzureCredential()
    kv_client = SecretClient(vault_url=kv_url, credential=credential)

    app_id = kv_client.get_secret(f"dqe-{env_code}-adb-spn-appID").value
    client_secret = kv_client.get_secret(f"dqe-{env_code}-adb-spn-pwd").value
    tenant_id = os.environ["TENANT_ID"]

    # Use SP to authenticate with Graph
    sp_cred = ClientSecretCredential(
        tenant_id=tenant_id,
        client_id=app_id,
        client_secret=client_secret
    )
    graph_client = GraphClient(credential=sp_cred)

    # Determine group name
    group_name = "PAG-dqe-p" if env_code == "p" else f"RG-DQE-{env_code}"

    group_res = graph_client.get(f"/groups?$filter=displayName eq '{group_name}'")
    group_id = group_res.json()["value"][0]["id"]

    members = []
    url = f"/groups/{group_id}/members?$select=userPrincipalName"
    while url:
        response = graph_client.get(url)
        data = response.json()
        members.extend([m["userPrincipalName"] for m in data.get("value", []) if "userPrincipalName" in m])
        url = data.get("@odata.nextLink", None)

    db_token = client_secret
    db_url = os.environ["DATABRICKS_URL"]
    headers = {
        "Authorization": f"Bearer {db_token}",
        "Content-Type": "application/scim+json"
    }

    r = requests.get(f"{db_url}/api/2.0/preview/scim/v2/Users", headers=headers)
    db_users = [u["userName"] for u in r.json().get("Resources", [])] if r.status_code == 200 else []

    to_add = set(members) - set(db_users)
    to_remove = set(db_users) - set(members)

    for user in to_add:
        body = {
            "userName": user,
            "emails": [{"value": user}],
            "entitlements": [{"value": "allow-cluster-create"}]
        }
        try:
            requests.post(f"{db_url}/api/2.0/preview/scim/v2/Users", headers=headers, json=body)
            logging.info(f"Added user: {user}")
        except Exception as e:
            logging.warning(f"Failed to add {user}: {e}")

    for user in to_remove:
        logging.warning(f"User {user} should be removed (manual cleanup or implement delete call).")

    logging.info("Databricks sync complete.")
