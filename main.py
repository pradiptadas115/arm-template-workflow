import requests
import json
from datetime import datetime
from deploy import deployment,get_order_options # ,get_credentials
from azure.common.credentials import ServicePrincipalCredentials

status_msg = list()
def run(event, context):
    return {}

def create_access_token(event):
    credentials = event.get("credentials")
    creds = ServicePrincipalCredentials(
        credentials["client_id"],
        credentials["client_secret"],
        tenant=credentials["tenant_id"],
    )
    return creds.token['access_token']
 

def arm_deployment(event,context):

    order = get_order_options(event)
    context.log("Order_ Handle: {}".format(order))
    context.log("Event: {}".format(event))
    template_name = order["template"]
    order_id = event["order_id"]
    try:
        dep_status=deployment(event, context, template_name)  # deployment
        context.log("Deployment status {}".format(dep_status),"DEBUG")
    except Exception as e:
        #print str(e)  
        context.log("Exception Azure Error {} ".format(str(e)),"DEBUG")   
        create_service_request_logs(context,order_id,str(e),"ERROR")

def get_azure_status(event,context):
    order = get_order_options(event)
    template_name = order["template"]
    order_id = event["order_id"]

    account_id = order["account_id"]
    subscription_id = order['subscription_id_'+account_id]
    resource_group = order['resource_id_'+account_id]
    access_token = create_access_token(event)

    bearer_token = 'Bearer ' + access_token
    header = {'Authorization': bearer_token}
    url = 'https://management.azure.com/subscriptions/'+subscription_id+'/resourcegroups/'+resource_group+'/providers/microsoft.resources/deployments/'+template_name+'?api-version=2018-05-01'
    r = requests.get(url, headers=header)

    resp_data = r.json()
    if 'error' in resp_data:
        create_service_request_logs(context,order_id,"Deployment Not Found","ERROR") 
        return {"Not_Found": True}
    else :
        complete_outer_msg = resp_data['name']+" is "+resp_data['properties']['provisioningState']

        #####################################################################################
        # create_service_request_logs(context, order_id, complete_outer_msg, "INFO")
        if resp_data['properties']['provisioningState'] in ('Running','Accepted','Succeeded'):
            if resp_data['properties']['provisioningState'] not in status_msg:
                create_service_request_logs(context, order_id, complete_outer_msg, "INFO")
            if resp_data['properties']['provisioningState'] is 'Succeeded':
                status_msg.append(resp_data['properties']['provisioningState'])
        context.log(str(status_msg),"debug")
        #####################################################################################
        if resp_data['properties']['provisioningState'] == "Succeeded":
            return {"Succeeded": True,"Running": False,"Failed": False }  
        elif resp_data['properties']['provisioningState'] == "Failed":
            return {"Failed": True,"Running": False, "Succeeded" : False }
        else :
            context.log("Properties {}".format(resp_data['properties']['dependencies']),"DEBUG")
            if resp_data['properties']['dependencies'] :

                for dependency in resp_data['properties']['dependencies'] :
                    url = dependency['id']
                    context.log("URL {}".format(url),"DEBUG")
                    inner_resource_api(event,context,access_token,url)

            return {"Running": True, "Failed": False, "Succeeded" : False}     

  


def create_service_request_logs(context,order_id,msg,severity):
    context.log("get_azure_status entered","DEBUG")
    payload = [
        {
            "severity": severity,
            "resource_id": "sc-order-"+str(order_id),
            "service": "nflex.flexer",
            "timestamp": datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
            "message": msg
        }
    ]
    r = context.api.post("/logs", payload)
    if r.status_code != 200:
        #print("Error sending logs to CMP: %s" % r.text)
        context.log("Error sending logs to CMP {}".format(r.text),"DEBUG")
        
    #context.log("Log api status code {}".format(r.status_code),"DEBUG")    
    return r.status_code 


def inner_resource_api(event,context,access_token,url):
    try:
        context.log("Inner resource api hit success","DEBUG")

        order_id = event["order_id"]
        bearer_token = 'Bearer ' + access_token

        context.log("Inner resource order_id {}".format(order_id),"DEBUG")
        context.log("Inner resource Bearer {}".format(access_token),"DEBUG")

        header = {'Authorization': bearer_token} 
        api_url ="https://management.azure.com"+url+"?api-version=2018-06-01"
        
        r = requests.get(api_url, headers=header)
        resp = r.json()

        #context.log("Inner Api all json {}".format(resp),"DEBUG")
        inner_status = resp['properties']['provisioningState']
        inner_resource_name = resp['name']
        complete_msg = inner_resource_name + " is " + inner_status

        context.log("Azure inner status {}".format(inner_status),"DEBUG")
        context.log("Azure inner name {}".format(inner_resource_name),"DEBUG")
        #########################################################################
        # create_service_request_logs(context, order_id, complete_msg, "INFO")
        if complete_msg not in status_msg :
            create_service_request_logs(context, order_id, complete_msg, "INFO")
            status_msg.append(complete_msg)
        #########################################################################

    except Exception as e:
        create_service_request_logs(context,order_id,str(e),"ERROR")

    return None      

def update_order(event,context):
    order = get_order_options(event)
    order_id = event['order_id']
    if order_id == None:
        raise Exception("Service catalog Order ID missing")

    context.log("Updating status/options for the Order: [{}]".format(order_id))

    resp = context.api.get("/orders/{}".format(order_id))
    json_result = resp.json()
    context.log(str(json_result),"debug")
    options = json_result["options"]
    payload = {
        "status": "complete",
    }

    template_name = order["template"]
    order_id = event["order_id"]

    account_id = order["account_id"]
    subscription_id = order['subscription_id_'+account_id]
    resource_group = order['resource_id_'+account_id]
    access_token = create_access_token()

    bearer_token = 'Bearer ' + access_token
    header = {'Authorization': bearer_token}
    url = 'https://management.azure.com/subscriptions/'+subscription_id+'/resourcegroups/'+resource_group+'/providers/microsoft.resources/deployments/'+template_name+'?api-version=2018-05-01'
    r = requests.get(url, headers=header)

    resp_data = r.json()

    response=""
    for item in resp_data['properties'].items():
        if "outputs" in item[0] :
            for k,v in item[1].items():
                response += str(k) +" -- "+str(v['value'])+"\n"
            options.append({
                "id": item[0],
                "key": item[0],
                "val": response,
            })
    payload["options"] = options

    resp = context.api.put("/orders/{}".format(order_id), payload)
    if resp.status_code != 200:
        context.log("Failed to update order: %s" % resp.text)
    


