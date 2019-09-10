# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class EdifactEnvelopeOverride(Model):
    """EdifactEnvelopeOverride.

    :param message_id: The message id on which this envelope settings has to
     be applied.
    :type message_id: str
    :param message_version: The message version on which this envelope
     settings has to be applied.
    :type message_version: str
    :param message_release: The message release version on which this
     envelope settings has to be applied.
    :type message_release: str
    :param message_association_assigned_code: The message association
     assigned code.
    :type message_association_assigned_code: str
    :param target_namespace: The target namespace on which this envelope
     settings has to be applied.
    :type target_namespace: str
    :param functional_group_id: The functional group id.
    :type functional_group_id: str
    :param sender_application_qualifier: The sender application qualifier.
    :type sender_application_qualifier: str
    :param sender_application_id: The sender application id.
    :type sender_application_id: str
    :param receiver_application_qualifier: The receiver application qualifier.
    :type receiver_application_qualifier: str
    :param receiver_application_id: The receiver application id.
    :type receiver_application_id: str
    :param controlling_agency_code: The controlling agency code.
    :type controlling_agency_code: str
    :param group_header_message_version: The group header message version.
    :type group_header_message_version: str
    :param group_header_message_release: The group header message release.
    :type group_header_message_release: str
    :param association_assigned_code: The association assigned code.
    :type association_assigned_code: str
    :param application_password: The application password.
    :type application_password: str
    """ 

    _attribute_map = {
        'message_id': {'key': 'messageId', 'type': 'str'},
        'message_version': {'key': 'messageVersion', 'type': 'str'},
        'message_release': {'key': 'messageRelease', 'type': 'str'},
        'message_association_assigned_code': {'key': 'messageAssociationAssignedCode', 'type': 'str'},
        'target_namespace': {'key': 'targetNamespace', 'type': 'str'},
        'functional_group_id': {'key': 'functionalGroupId', 'type': 'str'},
        'sender_application_qualifier': {'key': 'senderApplicationQualifier', 'type': 'str'},
        'sender_application_id': {'key': 'senderApplicationId', 'type': 'str'},
        'receiver_application_qualifier': {'key': 'receiverApplicationQualifier', 'type': 'str'},
        'receiver_application_id': {'key': 'receiverApplicationId', 'type': 'str'},
        'controlling_agency_code': {'key': 'controllingAgencyCode', 'type': 'str'},
        'group_header_message_version': {'key': 'groupHeaderMessageVersion', 'type': 'str'},
        'group_header_message_release': {'key': 'groupHeaderMessageRelease', 'type': 'str'},
        'association_assigned_code': {'key': 'associationAssignedCode', 'type': 'str'},
        'application_password': {'key': 'applicationPassword', 'type': 'str'},
    }

    def __init__(self, message_id=None, message_version=None, message_release=None, message_association_assigned_code=None, target_namespace=None, functional_group_id=None, sender_application_qualifier=None, sender_application_id=None, receiver_application_qualifier=None, receiver_application_id=None, controlling_agency_code=None, group_header_message_version=None, group_header_message_release=None, association_assigned_code=None, application_password=None):
        self.message_id = message_id
        self.message_version = message_version
        self.message_release = message_release
        self.message_association_assigned_code = message_association_assigned_code
        self.target_namespace = target_namespace
        self.functional_group_id = functional_group_id
        self.sender_application_qualifier = sender_application_qualifier
        self.sender_application_id = sender_application_id
        self.receiver_application_qualifier = receiver_application_qualifier
        self.receiver_application_id = receiver_application_id
        self.controlling_agency_code = controlling_agency_code
        self.group_header_message_version = group_header_message_version
        self.group_header_message_release = group_header_message_release
        self.association_assigned_code = association_assigned_code
        self.application_password = application_password
