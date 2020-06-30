import ast
import json
import re
import requests
from django.contrib.auth.decorators import login_required

from bot_registration.models import bot_details
from django.shortcuts import render
from django.http import JsonResponse
from django.utils.html import escape

from brain.utils import admin_history
from fwk.utils import log_error_msg
from api.forms import (LoadApiDataForm, ApiConfigForm)
from api.models import tbl_backend_ip_param_val, ApiData
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage
from brain.api_process import filter_api_output, output_formatter, replace_curly_braces_keys, str_to_json, xml_to_json


@login_required(login_url='/bot_registration/createbot')
def api_display(request, botid=None):
    show_bot_api = False

    if not botid:
        botid = request.session['bot_details']['botid']

    bot_detail = bot_details.objects.get(bot_apikey=botid)
    show_bot_api = bot_detail.show_bot_api_only



    return render(request, 'api_configuration.html', {
        'db_api_list': api_listing(request, botid=botid, show_bot_api=show_bot_api),
        'botid': botid,
        'bot_name': bot_detail.botname,
        'bot_username': request.user.username
    })


def api_listing(request, page=1, records_per_page=20, botid=None, search_text='', show_bot_api=False):
    # if page == '':  page = 10
    try:
        dictlist = []
        if page == '' or page == None:
            page = 1
        if not botid:
            botid = request.session['bot_details']['botid']
        if show_bot_api:
            db_api_list = ApiData.objects.filter(bot_id=botid)
        else:
            db_api_list = ApiData.objects.all()
        if search_text != None and search_text != '':
            for i in db_api_list:
                api_name = i['api_name']
                if search_text.lower() in ''.join(api_name).lower():
                    dictlist.append(i)
        else:
            for i in db_api_list:
                dictlist.append(i)
        paginator = Paginator(dictlist, records_per_page)
        try:
            users = paginator.page(page)
        except PageNotAnInteger:
            users = paginator.page(1)
        except EmptyPage:
            users = paginator.page(paginator.num_pages)
        return users
    except Exception as e:

        return "error"


def api_configuration(request, botid=None):
    if not botid:
        botid = request.session['bot_details']['botid']
    form = ApiConfigForm(request.GET)
    if form.is_valid():
        page = form.cleaned_data['page']
        search_text = form.cleaned_data['search_text']
        bot_detail = bot_details.objects.filter(bot_apikey=botid)[0]
        show_bot_api = bot_detail.show_bot_api_only
        return render(request, 'api_list.html', {
            'db_api_list': api_listing(request, botid=botid, page=page, search_text=search_text, show_bot_api=show_bot_api,),
            'botid': botid,
            'bot_name': bot_detail.botname,
            'bot_username': bot_detail.bot_username,
        })


def backend_services_fn(request, botid=None):
    try:
        if not botid:
            botid = request.session['bot_details']['botid']
        data_dict = json.loads(json.dumps(request.POST))
        authorization = ast.literal_eval(data_dict['authorization'])
        input_params_list = ast.literal_eval(data_dict['input_params'])
        headers = ast.literal_eval(data_dict['headers'])
        body = ast.literal_eval(data_dict['body'])
        output_params = ast.literal_eval(data_dict["output_params"])
        auth, header = auth_details(request, authorization, headers)
        #url = is_valid_url(data_dict["url"], headers, auth)
        url = data_dict["url"]
        if url:
            input_params = []
            for each in input_params_list:
                validation_obj = {}
                tbl_inp_para_validations = tbl_backend_ip_param_val.objects.get(validation=each['input_datatype'])
                validation_obj['validation'] = tbl_inp_para_validations.validation
                validation_obj['message_error'] = tbl_inp_para_validations.message_error
                validation_obj['regex'] = tbl_inp_para_validations.regex
                validation_obj['classification']=tbl_inp_para_validations.classification
                each['validations']=validation_obj
                del each['input_datatype']
                input_params.append(each)
            api_details = ApiData.objects.all()
            if api_details:
                if data_dict["Api_id"]:
                    api_details = ApiData.objects(id=data_dict["Api_id"])
                    if api_details:
                        update_status = api_details.update(
                            api_name=data_dict["api_name"],
                            url=data_dict["url"],
                            is_conversation=False,
                            request_type=data_dict["request_type"],
                            request_flow=data_dict["request_flow"],
                            bot_id=botid,
                            input_params=input_params,
                            input_formatter=data_dict['input_formatter'],
                            output_params=output_params,
                            authorization=authorization,
                            headers=headers,
                            body=body,
                            output_msg=data_dict['output_msg'],
                            output_formatter=data_dict['output_formatter'],
                            raw_data=data_dict['raw_data']
                        )
                        if update_status:
                            admin_history(botid, "API updated in the bot")
                            return JsonResponse({'message': 'Api successfully updated'})
                        else:
                            return JsonResponse({'message': 'Failed to update'})

                else:
                    api_details = ApiData.objects.filter(api_name=data_dict["api_name"],bot_id=botid)
                    if api_details:
                        return JsonResponse({'message': 'Api already present with that name choose different name'})
                    else:
                        api_obj = ApiData(
                            api_name=data_dict["api_name"],
                            url=data_dict["url"],
                            is_conversation=False,
                            request_type=data_dict["request_type"],
                            request_flow=data_dict["request_flow"],
                            bot_id=botid,
                            input_params=input_params,
                            input_formatter=data_dict['input_formatter'],
                            output_params=output_params,
                            authorization=authorization,
                            headers=headers,
                            body=body,
                            output_msg=data_dict['output_msg'],
                            output_formatter=data_dict['output_formatter'],
                            raw_data=data_dict['raw_data']
                        ).save()
                        if api_obj:
                            admin_history(botid,"API added in the bot")
                            return JsonResponse({'message': 'Api successfully inserted'})
                        else:
                            return JsonResponse({'message': 'Failed to insert api'})
            else:
                api_obj = ApiData(
                    api_name=data_dict["api_name"],
                    url=data_dict["url"],
                    is_conversation=False,
                    request_type=data_dict["request_type"],
                    request_flow=data_dict["request_flow"],
                    bot_id=botid,
                    input_params=input_params,
                    input_formatter=data_dict['input_formatter'],
                    output_params=output_params,
                    authorization=authorization,
                    headers=headers,
                    body=body,
                    output_msg=data_dict['output_msg'],
                    output_formatter=data_dict['output_formatter'],
                    raw_data=data_dict['raw_data']
                    ).save()
                if api_obj:
                    admin_history(botid, "API added in the bot")
                    return JsonResponse({'message': 'Api successfully inserted'})
                else:
                    return JsonResponse({'message': 'Failed to insert api'})
        else:
            return JsonResponse({'message': 'Failed to insert api'})
    except Exception as e:
        log_error_msg("backend_services_fn", str(e))
        return JsonResponse({'message': "Failed to insert api"})


def testing_get_api_call(api_url, auth, header):
    message = {"answer": "", "header": ""}
    try:
        if is_valid_url(api_url, header, auth):
            result1 = requests.get(url=api_url, auth=auth, headers=header, verify=False)
            if len(result1.content) < 10000:
                message["answer"] = result1.text
                message["header"] = result1.headers
                message["status"] = result1.status_code
            else:
                message['answer'] = 'Failed to load resource as the content size is too large'
        else:
            message['answer'] = 'Failed to download content. Please enter a valid url'
    except Exception as e:
        log_error_msg("testing_get_api_call", str(e))
        message['answer'] = str(e)
    return message


def testing_post_api_call(api_url, param, auth, header, raw_data):
    message = {"answer": "", "header": ""}
    try:
        if is_valid_url(api_url, header, auth):
            if len(raw_data) > 1:
                result1 = requests.post(url=api_url, auth=auth, headers=header, data=raw_data, verify=False)
            elif header and ('Content-Type' in header and header['Content-Type'] == 'application/json'):
                result1 = requests.post(url=api_url, auth=auth, headers=header, json=param, verify=False)
            else:
                result1 = requests.post(url=api_url, auth=auth, headers=header, data=param, verify=False)
            result1.raise_for_status()
            if len(result1.content) < 10000:
                message["answer"] = result1.text
                message["header"] = result1.headers
                message["status"] = result1.status_code
            else:
                message["answer"] = 'Failed to load resource as the content size is too large'
        else:
            message["answer"] = 'Failed to send content. Please enter a valid url'
    except Exception as e:
        log_error_msg("testing_post_api_call", str(e))
        message["answer"] = str(e)
    return message


def auth_details(request, auth_obj, headers):
    auth = ()
    if type(headers) is list:
        header = {key: value for obj in headers for key,value in obj.items()}
    if 'Bearer Token' in auth_obj:
        if header:
            header['Authorization'] = 'Bearer {0}'.format(auth_obj['Bearer Token'])

    elif 'Basic Auth' in auth_obj:
        auth = (auth_obj['Basic Auth']['username'], auth_obj['Basic Auth']['password'])

    return auth, header

def api_test_func(request, botid=None):

    api_reponse = api_filter_message = {}
    if not botid : botid = request.session['bot_details']['botid']
    api_details = json.loads(json.dumps(request.POST))
    input_params_list = ast.literal_eval(api_details['input_params'])
    output_param_list = ast.literal_eval(api_details["output_params"])
    authorization = ast.literal_eval(api_details["authorization"])
    headers = ast.literal_eval(api_details["headers"])
    raw_data = api_details['raw_data']
    #Assuming the test inputs provided by the admin will be of correct format , so no validation is done.
    param_dict = { input['input_parameter_name']: input["test_input"] for input in input_params_list}

    output_param = [each_output['output_parameter_key'] for each_output in output_param_list]
    output_param_name = {each_output['output_parameter_name'] : "__".join(each_output['output_parameter_key'] .split('.'))
                         for each_output in output_param_list}
    auth, header = auth_details(request,authorization, headers)
    body = ast.literal_eval(api_details['body'])
    if body:
        for obj in body:
            for key in obj:
                value = replace_curly_braces_keys(obj[key])
                if value not in param_dict:
                    param_dict[key] = value
    if api_details["request_type"].upper() == "GET":
        if len(param_dict) != 0:
            for values in param_dict:
                api_details["url"] = re.sub(str("{{" + values + "}}"), str(param_dict[values]), str(api_details["url"]))

        api_reponse = testing_get_api_call(api_details["url"], auth, header)

    elif api_details["request_type"].upper() == "POST":
        if len(param_dict) != 0 and raw_data:
            for values in param_dict:
                raw_data = re.sub(str("{{" + values + "}}"), str(param_dict[values]), str(raw_data))
        api_reponse = testing_post_api_call(api_details["url"], param_dict, auth, header, raw_data)

    if isinstance(api_reponse["answer"], str):
        if 'Content-Type' in header:
            respose_type = header['Content-Type']
        else:
            respose_type = ""

        if respose_type == "application/json":
            api_reponse["answer"] = str_to_json(api_reponse["answer"])
        elif respose_type == "application/xml" or respose_type == "text/xml":
            api_reponse["answer"] = xml_to_json(api_reponse["answer"])
        else:
            output = str_to_json(api_reponse["answer"])
            if output == api_reponse["answer"]:
                output = xml_to_json(api_reponse["answer"])
                if output != api_reponse["answer"]:
                    api_reponse["answer"] = output
            else:
                api_reponse["answer"] = output

    if api_reponse and len(output_param) != 0:
        api_filter_message['answer'] = filter_api_output(api_reponse["answer"], output_param)
        api_filter_message['header'] = api_reponse['header']
        api_filter_message['status'] = api_reponse['status']
    is_formatter_response = False
    if api_details['output_formatter']:
        if not api_filter_message:
            api_filter_message = api_reponse
        api_details["entellio_output"], is_formatter_response, context = output_formatter(request, api_filter_message, api_details['output_formatter'])
        if not is_formatter_response: api_details["entellio_output"] = api_filter_message["answer"]

    if not is_formatter_response and api_details['output_msg'] and output_param_name and api_filter_message['answer']:
        if isinstance(api_filter_message['answer'], dict):
            for param in output_param_name:
                api_details['output_msg'] = re.sub(str("{{" + param + "}}"),
                                                   str(api_filter_message['answer'][output_param_name[param]]),
                                                   str(api_details['output_msg'].strip()))
            api_details['entellio_output'] = api_details['output_msg']
        if isinstance(api_filter_message['answer'], list):
            for param in output_param_name:
                for value in api_filter_message['answer']:
                    api_details['output_msg'] = re.sub(str("{{" + param + "}}"), str(value[output_param_name[param]]),
                                                       str(api_details['output_msg'].strip()))
            api_details['entellio_output'] = api_details['output_msg']
    if 'entellio_output' not in api_details.keys():
        if api_filter_message: api_details['entellio_output'] = api_filter_message['answer']
        else: api_details['entellio_output'] = api_reponse['answer']
    api_details['message'] = api_reponse['answer']
    return JsonResponse(api_details)

def get_api_list(request, botid=None):
    show_bot_api = False
    if not botid:
        botid = request.session['bot_details']['botid']
    bot_detail = bot_details.objects.filter(bot_apikey=botid)[0]
    show_bot_api = bot_detail.show_bot_api_only
    if show_bot_api:
        api_data_list = ApiData.objects.filter(bot_id=botid)
    else:
        api_data_list = ApiData.objects.all()
    api_list=[]
    for api_obj in api_data_list:
        api_details = {"id": str(api_obj.id),
                       "api_name": api_obj.api_name,
                       "url": api_obj.url,
                       "request_type": api_obj.request_type,
                       "request_flow": api_obj.request_flow,
                       "input_params": api_obj.input_params,
                       "input_formatter": api_obj.input_formatter,
                       "output_params": api_obj.output_params,
                       "authorization": api_obj.authorization,
                       "headers": api_obj.headers,
                       "output_formatter": api_obj.output_formatter,
                       "raw_data": api_obj.raw_data}
        api_list.append(api_details)
    return JsonResponse(list(api_list), safe=False)

def load_backend_service_json(request, botid=None):
    api_details = {}
    load_api_form = LoadApiDataForm(request.POST)
    if load_api_form.is_valid():
        api_id = load_api_form.cleaned_data['api_id']
        if api_id:
            api_obj = ApiData.objects.get(id=api_id)
            if api_obj:
                api_details = {"api_name": api_obj['api_name'],
                               "url": api_obj['url'],
                               "request_type": api_obj['request_type'],
                               "request_flow": api_obj['request_flow'],
                               "input_params": api_obj['input_params'],
                               "input_formatter": api_obj['input_formatter'],
                               "output_params": api_obj['output_params'],
                               "authorization": api_obj['authorization'],
                               "headers": api_obj['headers'],
                               "body":api_obj['body'],
                               "output_msg":api_obj['output_msg'],
                               "output_formatter": api_obj['output_formatter'],
                               "raw_data": api_obj['raw_data']}

    return JsonResponse({'api_details': api_details}, safe=False)

def delete_backend_api_fn(request, botid=None):
    message = ""

    load_api_form = LoadApiDataForm(request.POST)
    if load_api_form.is_valid():
        api_id = load_api_form.cleaned_data['api_id']
        try:
            ApiData.objects.get(id=api_id).delete()
            message = "API Record Deleted successfully."
        except Exception as e:
            log_error_msg("delete_backend_api_fn", str(e))
            message = "Issue observed in deleting API.Please try again!!"
    return JsonResponse({'message': message})


def load_param_validations(request, botid=None):
    validations = []
    ip_param_validate = tbl_backend_ip_param_val.objects.all()
    for val in ip_param_validate:
        validations.append(escape(val.validation))

    return JsonResponse({"validations":validations})


def is_valid_url(url, headers, auth=None):
    """
    Does the url contain a downloadable resource
    """
    h = requests.head(url, allow_redirects=True, verify=False, auth=auth)
    header = h.headers
    content_type = header.get('content-type')
    if not content_type:
        if type(headers) is list:
            headers = {key: value for obj in headers for key, value in obj.items()}
        content_type = headers.get('Content-Type')
    accepted_types = ['application/atom+xml', 'application/json', 'application/javascript', 'application/octet-stream',
                      'application/base64', 'application/xml', 'application/x-www-form-urlencoded',
                      'multipart/alternative', 'multipart/form-data', 'multipart/mixed', 'text/css', 'text/html',
                      'text/plain', 'text/xml']
    if content_type.lower().split(";")[0] in accepted_types:
        return True
    return False
