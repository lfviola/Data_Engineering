
import os
import logging
import requests
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.subscription import SubscriptionClient
from msgraph.core import GraphClient
import azure.functions as func

def get_env_code():
    for source in [os.environ.get("AZURE_FUNCTION_APP_NAME", ""), os.environ.get("WEBSITE_SITE_NAME", ""), os.environ.get("AZURE_RESOURCE_GROUP", "")]:
        if source:
            parts = source.split("-")
            if len(parts) >= 3 and parts[0] == "dqe3":
                return parts[1]
    return "d"

def get_metadata():
    r = requests.get("http://169.254.169.254/metadata/instance?api-version=2021-02-01", headers={"Metadata": "true"})
    r.raise_for_status()
    data = r.json()["compute"]
    return {
        "subscriptionId": data["subscriptionId"],
        "resourceGroupName": data["resourceGroupName"],
        "location": data["location"]
    }

def get_tenant_id():
    r = requests.get(
        "http://169.254.169.254/metadata/identity/oauth2/token",
        headers={"Metadata": "true"},
        params={
            "api-version": "2018-02-01",
            "resource": "https://management.azure.com/"
        }
    )
    r.raise_for_status()
    return r.json()["tenant_id"]

def main(mytimer: func.TimerRequest) -> None:
    logging.info("Databricks sync function started")

    # Step 1: Determine environment code and workspace name
    credential = DefaultAzureCredential()
    env_code = get_env_code()
    workspace_name = f"dqe3-{env_code}-01-adb"
    kv_url = f"https://dqe3-{env_code}-kv.vault.azure.net"

    # Step 2: Retrieve subscription ID and resource group from metadata
    metadata = get_metadata()
    subscription_id = metadata["subscriptionId"]
    resource_group = metadata["resourceGroupName"]
    location = metadata["location"]

    # Step 3: Retrieve SP credentials from Key Vault
    kv_client = SecretClient(vault_url=kv_url, credential=credential)
    app_id = kv_client.get_secret(f"dqe-{env_code}-adb-spn-appID").value
    client_secret = kv_client.get_secret(f"dqe-{env_code}-adb-spn-pwd").value

    # Step 4: Authenticate to Graph with SP credentials
    tenant_id = get_tenant_id()
    from azure.identity import ClientSecretCredential
    sp_cred = ClientSecretCredential(tenant_id=tenant_id, client_id=app_id, client_secret=client_secret)
    graph_client = GraphClient(credential=sp_cred)

    # Step 5: Resolve Databricks workspace URL
    res_client = ResourceManagementClient(credential, subscription_id)
    ws = res_client.resources.get(
        resource_group_name=resource_group,
        resource_provider_namespace="Microsoft.Databricks",
        parent_resource_path="",
        resource_type="workspaces",
        resource_name=workspace_name,
        api_version="2023-05-01"
    )
    databricks_url = f"https://{ws.properties['workspaceUrl']}"

    # Step 6: Retrieve group members
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

    # Step 7: Retrieve current Databricks users
    headers = {
        "Authorization": f"Bearer {client_secret}",
        "Content-Type": "application/scim+json"
    }

    r = requests.get(f"{databricks_url}/api/2.0/preview/scim/v2/Users", headers=headers)
    db_users = r.json().get("Resources", []) if r.status_code == 200 else []
    db_usernames = [u["userName"] for u in db_users]

    to_add = set(members) - set(db_usernames)
    to_remove = set(db_usernames) - set(members)

    for user in to_add:
        body = {
            "userName": user,
            "emails": [{"value": user}],
            "entitlements": [{"value": "allow-cluster-create"}]
        }
        try:
            requests.post(f"{databricks_url}/api/2.0/preview/scim/v2/Users", headers=headers, json=body)
            logging.info(f"✅ Added user: {user}")
        except Exception as e:
            logging.warning(f"⚠️ Failed to add {user}: {e}")

    for db_user in db_users:
        user_name = db_user["userName"]
        if user_name in to_remove:
            user_id = db_user["id"]
            try:
                requests.delete(f"{databricks_url}/api/2.0/preview/scim/v2/Users/{user_id}", headers=headers)
                logging.info(f"🗑️ Removed user: {user_name}")
            except Exception as e:
                logging.warning(f"⚠️ Failed to remove {user_name}: {e}")

    logging.info("✅ Databricks sync function completed")
