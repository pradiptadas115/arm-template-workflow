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


class ContentHash(Model):
    """ContentHash.

    :param algorithm: The algorithm.
    :type algorithm: str
    :param value: The value.
    :type value: str
    """ 

    _attribute_map = {
        'algorithm': {'key': 'algorithm', 'type': 'str'},
        'value': {'key': 'value', 'type': 'str'},
    }

    def __init__(self, algorithm=None, value=None):
        self.algorithm = algorithm
        self.value = value