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


class RedisRegenerateKeyParameters(Model):
    """Specifies which redis access keys to reset.

    :param key_type: Which redis access key to reset. Possible values
     include: 'Primary', 'Secondary'
    :type key_type: str or :class:`RedisKeyType
     <azure.mgmt.redis.models.RedisKeyType>`
    """ 

    _validation = {
        'key_type': {'required': True},
    }

    _attribute_map = {
        'key_type': {'key': 'keyType', 'type': 'RedisKeyType'},
    }

    def __init__(self, key_type):
        self.key_type = key_type
