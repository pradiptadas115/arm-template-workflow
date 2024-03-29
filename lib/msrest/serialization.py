﻿# --------------------------------------------------------------------------
#
# Copyright (c) Microsoft Corporation. All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the ""Software""), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
# --------------------------------------------------------------------------

from base64 import b64decode, b64encode
import calendar
import datetime
import decimal
from enum import Enum
import json
import logging
import re
import sys
try:
    from urllib import quote
except ImportError:
    from urllib.parse import quote

import isodate

from .exceptions import (
    ValidationError,
    SerializationError,
    DeserializationError,
    raise_with_traceback)

try:
    basestring
except NameError:
    basestring = str

_LOGGER = logging.getLogger(__name__)


class UTC(datetime.tzinfo):
    """Time Zone info for handling UTC"""

    def utcoffset(self, dt):
        """UTF offset for UTC is 0."""
        return datetime.timedelta(0)

    def tzname(self, dt):
        """Timestamp representation."""
        return "Z"

    def dst(self, dt):
        """No daylight saving for UTC."""
        return datetime.timedelta(hours=1)


try:
    from datetime import timezone
    TZ_UTC = timezone.utc
except ImportError:
    TZ_UTC = UTC()

_FLATTEN = re.compile(r"(?<!\\)\.")

def attribute_transformer(key, attr_desc, value):
    """A key transfomer that returns the Python attribute.

    :param str key: The attribute name
    :param dict attr_desc: The attribute metadata
    :param object value: The value
    :returns: A key using attribute name
    """
    return (key, value)

def full_restapi_key_transformer(key, attr_desc, value):
    """A key transfomer that returns the full RestAPI key path.

    :param str _: The attribute name
    :param dict attr_desc: The attribute metadata
    :param object value: The value
    :returns: A list of keys using RestAPI syntax.
    """
    keys = _FLATTEN.split(attr_desc['key'])
    return ([_decode_attribute_map_key(k) for k in keys], value)

def last_restapi_key_transformer(key, attr_desc, value):
    """A key transfomer that returns the last RestAPI key.

    :param str _: The attribute name
    :param dict attr_desc: The attribute metadata
    :param object value: The value
    :returns: The last RestAPI key.
    """
    key, value = full_restapi_key_transformer(key, attr_desc, value)
    return (key[-1], value)

def _recursive_validate(attr_type, data):
    result = []
    if attr_type.startswith('[') and data is not None:
        for content in data:
            result += _recursive_validate(attr_type[1:-1], content)
    elif attr_type.startswith('{') and data is not None:
        for content in data.values():
            result += _recursive_validate(attr_type[1:-1], content)
    elif hasattr(data, '_validation'):
        return data.validate()
    return result


class Model(object):
    """Mixin for all client request body/response body models to support
    serialization and deserialization.
    """

    _subtype_map = {}
    _attribute_map = {}
    _validation = {}

    def __init__(self, *args, **kwargs):
        """Allow attribute setting via kwargs on initialization."""
        for k in kwargs:
            setattr(self, k, kwargs[k])

    def __eq__(self, other):
        """Compare objects by comparing all attributes."""
        if isinstance(other, self.__class__):
            return self.__dict__ == other.__dict__
        return False

    def __ne__(self, other):
        """Compare objects by comparing all attributes."""
        return not self.__eq__(other)

    def __str__(self):
        return str(self.__dict__)

    def validate(self):
        """Validate this model recursively and return a list of ValidationError.

        :returns: A list of validation error
        :rtype: list
        """
        validation_result = []
        for attr_name, value in [(attr, getattr(self, attr)) for attr in self._attribute_map]:
            attr_type = self._attribute_map[attr_name]['type']

            try:
                debug_name = "{}.{}".format(self.__class__.__name__, attr_name)
                Serializer.validate(value, debug_name, **self._validation.get(attr_name, {}))
            except ValidationError as validation_error:
                validation_result.append(validation_error)

            validation_result += _recursive_validate(attr_type, value)
        return validation_result

    def serialize(self, keep_readonly=False):
        """Return the JSON that would be sent to azure from this model.

        This is an alias to `as_dict(full_restapi_key_transformer, keep_readonly=False)`.

        :param bool keep_readonly: If you want to serialize the readonly attributes
        :returns: A dict JSON compatible object
        :rtype: dict
        """
        serializer = Serializer(self._infer_class_models())
        return serializer._serialize(self, keep_readonly=keep_readonly)

    def as_dict(self, keep_readonly=True, key_transformer=attribute_transformer):
        """Return a dict that can be JSONify using json.dump.

        Advanced usage might optionaly use a callback as parameter:

        .. code::python

            def my_key_transformer(key, attr_desc, value):
                return key

        Key is the attribute name used in Python. Attr_desc
        is a dict of metadata. Currently contains 'type' with the 
        msrest type and 'key' with the RestAPI encoded key.
        Value is the current value in this object.

        The string returned will be used to serialize the key.
        If the return type is a list, this is considered hierarchical
        result dict.

        See the three examples in this file:

        - attribute_transformer
        - full_restapi_key_transfomer
        - last_restapi_key_transformer

        :param function key_transformer: A key transformer function.
        :returns: A dict JSON compatible object
        :rtype: dict
        """
        serializer = Serializer(self._infer_class_models())
        return serializer._serialize(self, key_transformer=key_transformer, keep_readonly=keep_readonly)

    @classmethod
    def _infer_class_models(cls):
        try:
            str_models = cls.__module__.rsplit('.', 1)[0]
            models = sys.modules[str_models]
            client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
            if cls.__name__ not in client_models:
                raise ValueError("Not Autorest generated code")
        except Exception:
            # Assume it's not Autorest generated (tests?). Add ourselves as dependencies.
            client_models = {cls.__name__: cls}
        return client_models

    @classmethod
    def deserialize(cls, data):
        """Parse a dict using the RestAPI syntax and return a model.

        :param dict data: A dict using RestAPI structure
        :returns: An instance of this model
        :raises: DeserializationError if something went wrong
        """
        deserializer = Deserializer(cls._infer_class_models())
        return deserializer(cls.__name__, data)

    @classmethod
    def from_dict(cls, data, key_extractors=None):
        """Parse a dict using given key extractor return a model.

        By default consider key
        extractors (rest_key_case_insensitive_extractor, attribute_key_case_insensitive_extractor
        and last_rest_key_case_insensitive_extractor)

        :param dict data: A dict using RestAPI structure
        :returns: An instance of this model
        :raises: DeserializationError if something went wrong
        """
        deserializer = Deserializer(cls._infer_class_models())
        deserializer.key_extractors = [
            rest_key_case_insensitive_extractor,
            attribute_key_case_insensitive_extractor,
            last_rest_key_case_insensitive_extractor
        ] if key_extractors is None else key_extractors
        return deserializer(cls.__name__, data)

    @classmethod
    def _flatten_subtype(cls, key, objects):
        if '_subtype_map' not in cls.__dict__:
            return {}
        result = dict(cls._subtype_map[key])
        for valuetype in cls._subtype_map[key].values():
            result.update(objects[valuetype]._flatten_subtype(key, objects))
        return result

    @classmethod
    def _classify(cls, response, objects):
        """Check the class _subtype_map for any child classes.
        We want to ignore any inherited _subtype_maps.
        Remove the polymorphic key from the initial data.
        """
        for subtype_key in cls.__dict__.get('_subtype_map', {}).keys():
            subtype_value = None

            rest_api_response_key = cls._get_rest_key_parts(subtype_key)[-1]
            subtype_value = response.pop(rest_api_response_key, None) or response.pop(subtype_key, None)
            if subtype_value:
                # Try to match base class. Can be class name only
                # (bug to fix in Autorest to support x-ms-discriminator-name)
                if cls.__name__ == subtype_value:
                    return cls
                flatten_mapping_type = cls._flatten_subtype(subtype_key, objects)
                try:
                    return objects[flatten_mapping_type[subtype_value]]
                except KeyError:
                    raise DeserializationError("Subtype value {} has no mapping".format(subtype_value))
            else:
                raise DeserializationError("Discriminator {} cannot be absent or null".format(subtype_key))
        return cls

    @classmethod
    def _get_rest_key_parts(cls, attr_key):
        """Get the RestAPI key of this attr, split it and decode part
        :param str attr_key: Attribute key must be in attribute_map.
        :returns: A list of RestAPI part
        :rtype: list
        """
        rest_split_key = _FLATTEN.split(cls._attribute_map[attr_key]['key'])
        return [_decode_attribute_map_key(key_part) for key_part in rest_split_key]


def _decode_attribute_map_key(key):
    """This decode a key in an _attribute_map to the actual key we want to look at
       inside the received data.

       :param str key: A key string from the generated code
    """
    return key.replace('\\.', '.')


class Serializer(object):
    """Request object model serializer."""

    basic_types = {str: 'str', int: 'int', bool: 'bool', float: 'float'}
    days = {0: "Mon", 1: "Tue", 2: "Wed", 3: "Thu",
            4: "Fri", 5: "Sat", 6: "Sun"}
    months = {1: "Jan", 2: "Feb", 3: "Mar", 4: "Apr", 5: "May", 6: "Jun",
              7: "Jul", 8: "Aug", 9: "Sep", 10: "Oct", 11: "Nov", 12: "Dec"}
    validation = {
        "min_length": lambda x, y: len(x) < y,
        "max_length": lambda x, y: len(x) > y,
        "minimum": lambda x, y: x < y,
        "maximum": lambda x, y: x > y,
        "minimum_ex": lambda x, y: x <= y,
        "maximum_ex": lambda x, y: x >= y,
        "min_items": lambda x, y: len(x) < y,
        "max_items": lambda x, y: len(x) > y,
        "pattern": lambda x, y: not re.match(y, x, re.UNICODE),
        "unique": lambda x, y: len(x) != len(set(x)),
        "multiple": lambda x, y: x % y != 0
        }

    def __init__(self, classes=None):
        self.serialize_type = {
            'iso-8601': Serializer.serialize_iso,
            'rfc-1123': Serializer.serialize_rfc,
            'unix-time': Serializer.serialize_unix,
            'duration': Serializer.serialize_duration,
            'date': Serializer.serialize_date,
            'decimal': Serializer.serialize_decimal,
            'long': Serializer.serialize_long,
            'bytearray': Serializer.serialize_bytearray,
            'base64': Serializer.serialize_base64,
            'object': self.serialize_object,
            '[]': self.serialize_iter,
            '{}': self.serialize_dict
            }
        self.dependencies = dict(classes) if classes else {}
        self.key_transformer = full_restapi_key_transformer
        self.client_side_validation = True

    def _serialize(self, target_obj, data_type=None, **kwargs):
        """Serialize data into a string according to type.

        :param target_obj: The data to be serialized.
        :param str data_type: The type to be serialized from.
        :rtype: str, dict
        :raises: SerializationError if serialization fails.
        """
        key_transformer = kwargs.get("key_transformer", self.key_transformer)
        keep_readonly = kwargs.get("keep_readonly", False)
        if target_obj is None:
            return None

        serialized = {}
        attr_name = None
        class_name = target_obj.__class__.__name__

        if data_type:
            return self.serialize_data(
                target_obj, data_type, **kwargs)

        if not hasattr(target_obj, "_attribute_map"):
            data_type = type(target_obj).__name__
            if data_type in self.basic_types.values():
                return self.serialize_data(
                    target_obj, data_type, **kwargs)

        try:
            attributes = target_obj._attribute_map
            for attr, attr_desc in attributes.items():
                attr_name = attr
                if not keep_readonly and target_obj._validation.get(attr_name, {}).get('readonly', False):
                    continue
                try:
                    orig_attr = getattr(target_obj, attr)
                    keys, orig_attr = key_transformer(attr, attr_desc.copy(), orig_attr)
                    keys = keys if isinstance(keys, list) else [keys]
                    attr_type = attr_desc['type']
                    new_attr = self.serialize_data(
                        orig_attr, attr_type, **kwargs)

                    for k in reversed(keys):
                        unflattened = {k: new_attr}
                        new_attr = unflattened

                    _new_attr = new_attr
                    _serialized = serialized
                    for k in keys:
                        if k not in _serialized:
                            _serialized.update(_new_attr)
                        _new_attr = _new_attr[k]
                        _serialized = _serialized[k]
                except ValueError:
                    continue

        except (AttributeError, KeyError, TypeError) as err:
            msg = "Attribute {} in object {} cannot be serialized.\n{}".format(
                attr_name, class_name, str(target_obj))
            raise_with_traceback(SerializationError, msg, err)
        else:
            return serialized

    def body(self, data, data_type, **kwargs):
        """Serialize data intended for a request body.

        :param data: The data to be serialized.
        :param str data_type: The type to be serialized from.
        :rtype: dict
        :raises: SerializationError if serialization fails.
        :raises: ValueError if data is None
        """
        if data is None:
            raise ValidationError("required", "body", True)

        # Just in case this is a dict
        internal_data_type = data_type.strip('[]{}')
        if internal_data_type in self.dependencies and not isinstance(internal_data_type, Enum):
            try:
                deserializer = Deserializer(self.dependencies)
                deserializer.key_extractors = [
                    rest_key_case_insensitive_extractor,
                    attribute_key_case_insensitive_extractor,
                    last_rest_key_case_insensitive_extractor
                ]
                data = deserializer(data_type, data)
            except DeserializationError as err:
                raise_with_traceback(
                    SerializationError, "Unable to build a model: "+str(err), err)

        if self.client_side_validation:
            errors = _recursive_validate(data_type, data)
            if errors:
                raise errors[0]
        return self._serialize(data, data_type, **kwargs)

    def url(self, name, data, data_type, **kwargs):
        """Serialize data intended for a URL path.

        :param data: The data to be serialized.
        :param str data_type: The type to be serialized from.
        :rtype: str
        :raises: TypeError if serialization fails.
        :raises: ValueError if data is None
        """
        if self.client_side_validation:
            data = self.validate(data, name, required=True, **kwargs)
        try:
            output = self.serialize_data(data, data_type, **kwargs)
            if data_type == 'bool':
                output = json.dumps(output)

            if kwargs.get('skip_quote') is True:
                output = str(output)
            else:
                output = quote(str(output), safe='')
        except SerializationError:
            raise TypeError("{} must be type {}.".format(name, data_type))
        else:
            return output

    def query(self, name, data, data_type, **kwargs):
        """Serialize data intended for a URL query.

        :param data: The data to be serialized.
        :param str data_type: The type to be serialized from.
        :rtype: str
        :raises: TypeError if serialization fails.
        :raises: ValueError if data is None
        """
        if self.client_side_validation:
            data = self.validate(data, name, required=True, **kwargs)
        try:
            if data_type in ['[str]']:
                data = ["" if d is None else d for d in data]

            output = self.serialize_data(data, data_type, **kwargs)
            if data_type == 'bool':
                output = json.dumps(output)
            if kwargs.get('skip_quote') is True:
                output = str(output)
            else:
                output = quote(str(output), safe='')
        except SerializationError:
            raise TypeError("{} must be type {}.".format(name, data_type))
        else:
            return str(output)

    def header(self, name, data, data_type, **kwargs):
        """Serialize data intended for a request header.

        :param data: The data to be serialized.
        :param str data_type: The type to be serialized from.
        :rtype: str
        :raises: TypeError if serialization fails.
        :raises: ValueError if data is None
        """
        if self.client_side_validation:
            data = self.validate(data, name, required=True, **kwargs)
        try:
            if data_type in ['[str]']:
                data = ["" if d is None else d for d in data]

            output = self.serialize_data(data, data_type, **kwargs)
            if data_type == 'bool':
                output = json.dumps(output)
        except SerializationError:
            raise TypeError("{} must be type {}.".format(name, data_type))
        else:
            return str(output)

    @classmethod
    def validate(cls, data, name, **kwargs):
        """Validate that a piece of data meets certain conditions"""
        required = kwargs.get('required', False)
        if required and data is None:
            raise ValidationError("required", name, True)
        elif data is None:
            return
        elif kwargs.get('readonly'):
            return

        try:
            for key, value in kwargs.items():
                validator = cls.validation.get(key, lambda x, y: False)
                if validator(data, value):
                    raise ValidationError(key, name, value)
        except TypeError:
            raise ValidationError("unknown", name, "unknown")
        else:
            return data

    def serialize_data(self, data, data_type, **kwargs):
        """Serialize generic data according to supplied data type.

        :param data: The data to be serialized.
        :param str data_type: The type to be serialized from.
        :param bool required: Whether it's essential that the data not be
         empty or None
        :raises: AttributeError if required data is None.
        :raises: ValueError if data is None
        :raises: SerializationError if serialization fails.
        """
        if data is None:
            raise ValueError("No value for given attribute")

        try:
            if data_type in self.basic_types.values():
                return self.serialize_basic(data, data_type)

            elif data_type in self.serialize_type:
                return self.serialize_type[data_type](data, **kwargs)

            # If dependencies is empty, try with current data class
            # It has to be a subclass of Enum anyway
            enum_type = self.dependencies.get(data_type, data.__class__)
            if issubclass(enum_type, Enum):
                return Serializer.serialize_enum(data, enum_obj=enum_type)

            iter_type = data_type[0] + data_type[-1]
            if iter_type in self.serialize_type:
                return self.serialize_type[iter_type](
                    data, data_type[1:-1], **kwargs)

        except (ValueError, TypeError) as err:
            msg = "Unable to serialize value: {!r} as type: {!r}."
            raise_with_traceback(
                SerializationError, msg.format(data, data_type), err)
        else:
            return self._serialize(data, **kwargs)

    def serialize_basic(self, data, data_type):
        """Serialize basic builting data type.
        Serializes objects to str, int, float or bool.

        :param data: Object to be serialized.
        :param str data_type: Type of object in the iterable.
        """
        if data_type == 'str':
            return self.serialize_unicode(data)
        return eval(data_type)(data)

    def serialize_unicode(self, data):
        """Special handling for serializing unicode strings in Py2.
        Encode to UTF-8 if unicode, otherwise handle as a str.

        :param data: Object to be serialized.
        :rtype: str
        """
        try:
            return data.value
        except AttributeError:
            pass
        try:
            if isinstance(data, unicode):
                return data.encode(encoding='utf-8')
        except NameError:
            return str(data)
        else:
            return str(data)

    def serialize_iter(self, data, iter_type, div=None, **kwargs):
        """Serialize iterable.

        :param list attr: Object to be serialized.
        :param str iter_type: Type of object in the iterable.
        :param bool required: Whether the objects in the iterable must
         not be None or empty.
        :param str div: If set, this str will be used to combine the elements
         in the iterable into a combined string. Default is 'None'.
        :rtype: list, str
        """
        if isinstance(data, str):
            raise SerializationError("Refuse str type as a valid iter type.")
        serialized = []
        for d in data:
            try:
                serialized.append(
                    self.serialize_data(d, iter_type, **kwargs))
            except ValueError:
                serialized.append(None)

        if div:
            serialized = ['' if s is None else s for s in serialized]
            serialized = div.join(serialized)
        return serialized

    def serialize_dict(self, attr, dict_type, **kwargs):
        """Serialize a dictionary of objects.

        :param dict attr: Object to be serialized.
        :param str dict_type: Type of object in the dictionary.
        :param bool required: Whether the objects in the dictionary must
         not be None or empty.
        :rtype: dict
        """
        serialized = {}
        for key, value in attr.items():
            try:
                serialized[self.serialize_unicode(key)] = self.serialize_data(
                    value, dict_type, **kwargs)
            except ValueError:
                serialized[self.serialize_unicode(key)] = None
        return serialized

    def serialize_object(self, attr, **kwargs):
        """Serialize a generic object.
        This will be handled as a dictionary. If object passed in is not
        a basic type (str, int, float, dict, list) it will simply be
        cast to str.

        :param dict attr: Object to be serialized.
        :rtype: dict or str
        """
        if attr is None:
            return None
        obj_type = type(attr)
        if obj_type in self.basic_types:
            return self.serialize_basic(attr, self.basic_types[obj_type])
        # If it's a model or I know this dependency, serialize as a Model
        elif obj_type in self.dependencies.values() or isinstance(obj_type, Model):
            return self._serialize(attr)

        if obj_type == dict:
            serialized = {}
            for key, value in attr.items():
                try:
                    serialized[self.serialize_unicode(key)] = self.serialize_object(
                        value, **kwargs)
                except ValueError:
                    serialized[self.serialize_unicode(key)] = None
            return serialized

        if obj_type == list:
            serialized = []
            for obj in attr:
                try:
                    serialized.append(self.serialize_object(
                        obj, **kwargs))
                except ValueError:
                    pass
            return serialized
        return str(attr)

    @staticmethod
    def serialize_enum(attr, enum_obj=None):
        try:
            result = attr.value
        except AttributeError:
            result = attr
        try:
            enum_obj(result)
            return result
        except ValueError:
            for enum_value in enum_obj:
                if enum_value.value.lower() == str(attr).lower():
                    return enum_value.value
            error = "{!r} is not valid value for enum {!r}"
            raise SerializationError(error.format(attr, enum_obj))

    @staticmethod
    def serialize_bytearray(attr, **kwargs):
        """Serialize bytearray into base-64 string.

        :param attr: Object to be serialized.
        :rtype: str
        """
        return b64encode(attr).decode()

    @staticmethod
    def serialize_base64(attr, **kwargs):
        """Serialize str into base-64 string.

        :param attr: Object to be serialized.
        :rtype: str
        """
        encoded = b64encode(attr).decode('ascii')
        return encoded.strip('=').replace('+', '-').replace('/', '_')

    @staticmethod
    def serialize_decimal(attr, **kwargs):
        """Serialize Decimal object to float.

        :param attr: Object to be serialized.
        :rtype: float
        """
        return float(attr)

    @staticmethod
    def serialize_long(attr, **kwargs):
        """Serialize long (Py2) or int (Py3).

        :param attr: Object to be serialized.
        :rtype: int/long
        """
        try:
            return long(attr)
        except NameError:
            return int(attr)

    @staticmethod
    def serialize_date(attr, **kwargs):
        """Serialize Date object into ISO-8601 formatted string.

        :param Date attr: Object to be serialized.
        :rtype: str
        """
        if isinstance(attr, str):
            attr = isodate.parse_date(attr)
        t = "{:04}-{:02}-{:02}".format(attr.year, attr.month, attr.day)
        return t

    @staticmethod
    def serialize_duration(attr, **kwargs):
        """Serialize TimeDelta object into ISO-8601 formatted string.

        :param TimeDelta attr: Object to be serialized.
        :rtype: str
        """
        if isinstance(attr, str):
            attr = isodate.parse_duration(attr)
        return isodate.duration_isoformat(attr)

    @staticmethod
    def serialize_rfc(attr, **kwargs):
        """Serialize Datetime object into RFC-1123 formatted string.

        :param Datetime attr: Object to be serialized.
        :rtype: str
        :raises: TypeError if format invalid.
        """
        try:
            if not attr.tzinfo:
                _LOGGER.warning(
                    "Datetime with no tzinfo will be considered UTC.")
            utc = attr.utctimetuple()
        except AttributeError:
            raise TypeError("RFC1123 object must be valid Datetime object.")

        return "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT".format(
            Serializer.days[utc.tm_wday], utc.tm_mday,
            Serializer.months[utc.tm_mon], utc.tm_year,
            utc.tm_hour, utc.tm_min, utc.tm_sec)

    @staticmethod
    def serialize_iso(attr, **kwargs):
        """Serialize Datetime object into ISO-8601 formatted string.

        :param Datetime attr: Object to be serialized.
        :rtype: str
        :raises: SerializationError if format invalid.
        """
        if isinstance(attr, str):
            attr = isodate.parse_datetime(attr)
        try:
            if not attr.tzinfo:
                _LOGGER.warning(
                    "Datetime with no tzinfo will be considered UTC.")
            utc = attr.utctimetuple()
            if utc.tm_year > 9999 or utc.tm_year < 1:
                raise OverflowError("Hit max or min date")

            microseconds = str(float(attr.microsecond)*1e-6)[1:].ljust(4, '0')
            date = "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}".format(
                utc.tm_year, utc.tm_mon, utc.tm_mday,
                utc.tm_hour, utc.tm_min, utc.tm_sec)
            return date + microseconds + 'Z'
        except (ValueError, OverflowError) as err:
            msg = "Unable to serialize datetime object."
            raise_with_traceback(SerializationError, msg, err)
        except AttributeError as err:
            msg = "ISO-8601 object must be valid Datetime object."
            raise_with_traceback(TypeError, msg, err)

    @staticmethod
    def serialize_unix(attr, **kwargs):
        """Serialize Datetime object into IntTime format.
        This is represented as seconds.

        :param Datetime attr: Object to be serialized.
        :rtype: int
        :raises: SerializationError if format invalid
        """
        if isinstance(attr, int):
            return attr
        try:
            if not attr.tzinfo:
                _LOGGER.warning(
                    "Datetime with no tzinfo will be considered UTC.")
            return int(calendar.timegm(attr.utctimetuple()))
        except AttributeError:
            raise TypeError("Unix time object must be valid Datetime object.")

def rest_key_extractor(attr, attr_desc, data):
    key = attr_desc['key']
    working_data = data

    while '.' in key:
        dict_keys = _FLATTEN.split(key)
        if len(dict_keys) == 1:
            key = _decode_attribute_map_key(dict_keys[0])
            break
        working_key = _decode_attribute_map_key(dict_keys[0])
        working_data = working_data.get(working_key, data)
        key = '.'.join(dict_keys[1:])

    return working_data.get(key)

def rest_key_case_insensitive_extractor(attr, attr_desc, data):
    key = attr_desc['key']
    working_data = data

    while '.' in key:
        dict_keys = _FLATTEN.split(key)
        if len(dict_keys) == 1:
            key = _decode_attribute_map_key(dict_keys[0])
            break
        working_key = _decode_attribute_map_key(dict_keys[0])
        working_data = attribute_key_case_insensitive_extractor(working_key, None, working_data)
        key = '.'.join(dict_keys[1:])

    if working_data:
        return attribute_key_case_insensitive_extractor(key, None, working_data)

def last_rest_key_extractor(attr, attr_desc, data):
    key = attr_desc['key']
    dict_keys = _FLATTEN.split(key)
    return attribute_key_extractor(dict_keys[-1], None, data)

def last_rest_key_case_insensitive_extractor(attr, attr_desc, data):
    key = attr_desc['key']
    dict_keys = _FLATTEN.split(key)
    return attribute_key_case_insensitive_extractor(dict_keys[-1], None, data)

def attribute_key_extractor(attr, _, data):
    return data.get(attr)

def attribute_key_case_insensitive_extractor(attr, _, data):
    found_key = None
    lower_attr = attr.lower()
    for key in data:
        if lower_attr == key.lower():
            found_key = key
            break

    return data.get(found_key)

class Deserializer(object):
    """Response object model deserializer.

    :param dict classes: Class type dictionary for deserializing
     complex types.
    """

    basic_types = {str: 'str', int: 'int', bool: 'bool', float: 'float'}
    valid_date = re.compile(
        r'\d{4}[-]\d{2}[-]\d{2}T\d{2}:\d{2}:\d{2}'
        r'\.?\d*Z?[-+]?[\d{2}]?:?[\d{2}]?')

    def __init__(self, classes=None):
        self.deserialize_type = {
            'iso-8601': Deserializer.deserialize_iso,
            'rfc-1123': Deserializer.deserialize_rfc,
            'unix-time': Deserializer.deserialize_unix,
            'duration': Deserializer.deserialize_duration,
            'date': Deserializer.deserialize_date,
            'decimal': Deserializer.deserialize_decimal,
            'long': Deserializer.deserialize_long,
            'bytearray': Deserializer.deserialize_bytearray,
            'base64': Deserializer.deserialize_base64,
            'object': self.deserialize_object,
            '[]': self.deserialize_iter,
            '{}': self.deserialize_dict
            }
        self.deserialize_expected_types = {
            'duration': (isodate.Duration, datetime.timedelta)
        }
        self.dependencies = dict(classes) if classes else {}
        self.key_extractors = [
            rest_key_extractor
        ]

    def __call__(self, target_obj, response_data, content_type=None):
        """Call the deserializer to process a REST response.

        :param str target_obj: Target data type to deserialize to.
        :param requests.Response response_data: REST response object.
        :param str content_type: Swagger "produces" if available.
        :raises: DeserializationError if deserialization fails.
        :return: Deserialized object.
        """
        # This is already a model, go recursive just in case
        if hasattr(response_data, "_attribute_map"):
            constants = [name for name, config in getattr(response_data, '_validation', {}).items()
                         if config.get('constant')]
            try:
                for attr, mapconfig in response_data._attribute_map.items():
                    if attr in constants:
                        continue
                    value = getattr(response_data, attr)
                    if value is None:
                        continue
                    local_type = mapconfig['type']
                    internal_data_type = local_type.strip('[]{}')
                    if internal_data_type not in self.dependencies or isinstance(internal_data_type, Enum):
                        continue
                    setattr(
                        response_data,
                        attr,
                        self(local_type, value)
                    )
                return response_data
            except AttributeError:
                return

        data = self._unpack_content(response_data, content_type)
        response, class_name = self._classify_target(target_obj, data)

        if isinstance(response, basestring):
            return self.deserialize_data(data, response)
        elif isinstance(response, type) and issubclass(response, Enum):
            return self.deserialize_enum(data, response)

        if data is None:
            return data
        try:
            attributes = response._attribute_map
            d_attrs = {}
            for attr, attr_desc in attributes.items():

                raw_value = None
                for key_extractor in self.key_extractors:
                    found_value = key_extractor(attr, attr_desc, data)
                    if found_value is not None:
                        if raw_value is not None and raw_value != found_value:
                            raise KeyError('Use twice the key: "{}"'.format(attr))
                        raw_value = found_value

                value = self.deserialize_data(raw_value, attr_desc['type'])
                d_attrs[attr] = value
        except (AttributeError, TypeError, KeyError) as err:
            msg = "Unable to deserialize to object: " + class_name
            raise_with_traceback(DeserializationError, msg, err)
        else:
            return self._instantiate_model(response, d_attrs)

    def _classify_target(self, target, data):
        """Check to see whether the deserialization target object can
        be classified into a subclass.
        Once classification has been determined, initialize object.

        :param str target: The target object type to deserialize to.
        :param str/dict data: The response data to deseralize.
        """
        if target is None:
            return None, None

        if isinstance(target, basestring):
            try:
                target = self.dependencies[target]
            except KeyError:
                return target, target

        try:
            target = target._classify(data, self.dependencies)
        except AttributeError:
            pass  # Target is not a Model, no classify
        return target, target.__class__.__name__

    JSON_MIMETYPES = [
        'application/json',
        'text/json' # Because we're open minded people...
    ]

    @staticmethod
    def _unpack_content(raw_data, content_type=None):
        """Extract data from the body of a REST response object.

        If raw_data is a requests.Response object, follow Content-Type
        to parse (ignore content_type parameter).
        If bytes is given, decode using UTF8 first. 
        If content_type is given, try to parse.
        Otherwise, return initial data.
        We assume everything is UTF8 (BOM acceptable).

        :param raw_data: Data to be processed.
        :param content_type: How to parse if raw_data is a string/bytes.
        :raises JSONDecodeError: If JSON is requested and parsing is impossible.
        :raises UnicodeDecodeError: If bytes is not UTF8
        """

        if hasattr(raw_data, 'text'): # Our requests.Response test
            # Try to use content-type from headers if available
            if 'content-type' in raw_data.headers:
                content_type = raw_data.headers['content-type'].split(";")[0].strip().lower()
            # Ouch, this server did not declare what it sent...
            # Use Swagger "produces", which will be passed to "content_type" here
            # If "content_type" also is empty, this means that it's an old version
            # of Autorest for Python, let's guess it's JSON...
            # Also, since Autorest was considering that an empty body was a valid JSON,
            # need that test as well....
            elif not content_type:
                if not raw_data.text:
                    return None
                content_type = "application/json"
            # Whatever content type, data is readable (not bytes). Get it as a string.
            data = raw_data.text
        elif raw_data and isinstance(raw_data, bytes):
            data = raw_data.decode(encoding='utf-8-sig')
        else:
            data = raw_data

        if content_type in Deserializer.JSON_MIMETYPES:
            try:
                return json.loads(data)
            except ValueError as err:
                raise DeserializationError("JSON is invalid: {}".format(err), err)
        elif "xml" in (content_type or []):
            raise DeserializationError("Do not support XML right now")
        return data

    def _instantiate_model(self, response, attrs):
        """Instantiate a response model passing in deserialized args.

        :param response: The response model class.
        :param d_attrs: The deserialized response attributes.
        """
        if callable(response):
            subtype = getattr(response, '_subtype_map', {})
            try:
                readonly = [k for k, v in response._validation.items()
                            if v.get('readonly')]
                const = [k for k, v in response._validation.items()
                         if v.get('constant')]
                kwargs = {k: v for k, v in attrs.items()
                          if k not in subtype and k not in readonly + const}
                response_obj = response(**kwargs)
                for attr in readonly:
                    setattr(response_obj, attr, attrs.get(attr))
                return response_obj
            except TypeError as err:
                msg = "Unable to deserialize {} into model {}. ".format(
                    kwargs, response)
                raise DeserializationError(msg + str(err))
        else:
            try:
                for attr, value in attrs.items():
                    setattr(response, attr, value)
                return response
            except Exception as exp:
                msg = "Unable to populate response model. "
                msg += "Type: {}, Error: {}".format(type(response), exp)
                raise DeserializationError(msg)

    def deserialize_data(self, data, data_type):
        """Process data for deserialization according to data type.

        :param str data: The response string to be deserialized.
        :param str data_type: The type to deserialize to.
        :raises: DeserializationError if deserialization fails.
        :return: Deserialized object.
        """
        if data is None:
            return data

        try:
            if not data_type:
                return data
            if data_type in self.basic_types.values():
                return self.deserialize_basic(data, data_type)
            if data_type in self.deserialize_type:
                if isinstance(data, self.deserialize_expected_types.get(data_type, tuple())):
                    return data
                data_val = self.deserialize_type[data_type](data)
                return data_val

            iter_type = data_type[0] + data_type[-1]
            if iter_type in self.deserialize_type:
                return self.deserialize_type[iter_type](data, data_type[1:-1])

            obj_type = self.dependencies[data_type]
            if issubclass(obj_type, Enum):
                return self.deserialize_enum(data, obj_type)

        except (ValueError, TypeError, AttributeError) as err:
            msg = "Unable to deserialize response data."
            msg += " Data: {}, {}".format(data, data_type)
            raise_with_traceback(DeserializationError, msg, err)
        else:
            return self(obj_type, data)

    def deserialize_iter(self, attr, iter_type):
        """Deserialize an iterable.

        :param list attr: Iterable to be deserialized.
        :param str iter_type: The type of object in the iterable.
        :rtype: list
        """
        if attr is None:
            return None
        if not isinstance(attr, (list, set)):
            raise DeserializationError("Cannot deserialize as [{}] an object of type {}".format(
                iter_type,
                type(attr)
            ))
        return [self.deserialize_data(a, iter_type) for a in attr]

    def deserialize_dict(self, attr, dict_type):
        """Deserialize a dictionary.

        :param dict/list attr: Dictionary to be deserialized. Also accepts
         a list of key, value pairs.
        :param str dict_type: The object type of the items in the dictionary.
        :rtype: dict
        """
        if isinstance(attr, list):
            return {x['key']: self.deserialize_data(
                x['value'], dict_type) for x in attr}
        return {k: self.deserialize_data(
            v, dict_type) for k, v in attr.items()}

    def deserialize_object(self, attr, **kwargs):
        """Deserialize a generic object.
        This will be handled as a dictionary.

        :param dict attr: Dictionary to be deserialized.
        :rtype: dict
        :raises: TypeError if non-builtin datatype encountered.
        """
        if attr is None:
            return None
        if isinstance(attr, basestring):
            return self.deserialize_basic(attr, 'str')
        obj_type = type(attr)
        if obj_type in self.basic_types:
            return self.deserialize_basic(attr, self.basic_types[obj_type])

        if obj_type == dict:
            deserialized = {}
            for key, value in attr.items():
                try:
                    deserialized[key] = self.deserialize_object(
                        value, **kwargs)
                except ValueError:
                    deserialized[key] = None
            return deserialized

        if obj_type == list:
            deserialized = []
            for obj in attr:
                try:
                    deserialized.append(self.deserialize_object(
                        obj, **kwargs))
                except ValueError:
                    pass
            return deserialized

        else:
            error = "Cannot deserialize generic object with type: "
            raise TypeError(error + str(obj_type))

    def deserialize_basic(self, attr, data_type):
        """Deserialize baisc builtin data type from string.
        Will attempt to convert to str, int, float and bool.
        This function will also accept '1', '0', 'true' and 'false' as
        valid bool values.

        :param str attr: response string to be deserialized.
        :param str data_type: deserialization data type.
        :rtype: str, int, float or bool
        :raises: TypeError if string format is not valid.
        """
        if data_type == 'bool':
            if attr in [True, False, 1, 0]:
                return bool(attr)
            elif isinstance(attr, basestring):
                if attr.lower() in ['true', '1']:
                    return True
                elif attr.lower() in ['false', '0']:
                    return False
            raise TypeError("Invalid boolean value: {}".format(attr))

        if data_type == 'str':
            return self.deserialize_unicode(attr)
        return eval(data_type)(attr)

    def deserialize_unicode(self, data):
        """Preserve unicode objects in Python 2, otherwise return data
        as a string.

        :param str data: response string to be deserialized.
        :rtype: str or unicode
        """
        # We might be here because we have an enum modeled as string,
        # and we try to deserialize a partial dict with enum inside
        if isinstance(data, Enum):
            return data

        # Consider this is real string
        try:
            if isinstance(data, unicode):
                return data
        except NameError:
            return str(data)
        else:
            return str(data)

    def deserialize_enum(self, data, enum_obj):
        """Deserialize string into enum object.

        :param str data: response string to be deserialized.
        :param Enum enum_obj: Enum object to deserialize to.
        :rtype: Enum
        :raises: DeserializationError if string is not valid enum value.
        """
        if isinstance(data, enum_obj):
            return data
        if isinstance(data, int):
            # Workaround. We might consider remove it in the future.
            # https://github.com/Azure/azure-rest-api-specs/issues/141
            try:
                return list(enum_obj.__members__.values())[data]
            except IndexError:
                error = "{!r} is not a valid index for enum {!r}"
                raise DeserializationError(error.format(data, enum_obj))
        try:
            return enum_obj(str(data))
        except ValueError:
            for enum_value in enum_obj:
                if enum_value.value.lower() == str(data).lower():
                    return enum_value
            error = "{!r} is not valid value for enum {!r}"
            raise DeserializationError(error.format(data, enum_obj))

    @staticmethod
    def deserialize_bytearray(attr):
        """Deserialize string into bytearray.

        :param str attr: response string to be deserialized.
        :rtype: bytearray
        :raises: TypeError if string format invalid.
        """
        return bytearray(b64decode(attr))

    @staticmethod
    def deserialize_base64(attr):
        """Deserialize base64 encoded string into string.

        :param str attr: response string to be deserialized.
        :rtype: bytearray
        :raises: TypeError if string format invalid.
        """
        padding = '=' * (3 - (len(attr) + 3) % 4)
        attr = attr + padding
        encoded = attr.replace('-', '+').replace('_', '/')
        return b64decode(encoded)

    @staticmethod
    def deserialize_decimal(attr):
        """Deserialize string into Decimal object.

        :param str attr: response string to be deserialized.
        :rtype: Decimal
        :raises: DeserializationError if string format invalid.
        """
        try:
            return decimal.Decimal(attr)
        except decimal.DecimalException as err:
            msg = "Invalid decimal {}".format(attr)
            raise_with_traceback(DeserializationError, msg, err)

    @staticmethod
    def deserialize_long(attr):
        """Deserialize string into long (Py2) or int (Py3).

        :param str attr: response string to be deserialized.
        :rtype: long or int
        :raises: ValueError if string format invalid.
        """
        try:
            return long(attr)
        except NameError:
            return int(attr)

    @staticmethod
    def deserialize_duration(attr):
        """Deserialize ISO-8601 formatted string into TimeDelta object.

        :param str attr: response string to be deserialized.
        :rtype: TimeDelta
        :raises: DeserializationError if string format invalid.
        """
        try:
            duration = isodate.parse_duration(attr)
        except(ValueError, OverflowError, AttributeError) as err:
            msg = "Cannot deserialize duration object."
            raise_with_traceback(DeserializationError, msg, err)
        else:
            return duration

    @staticmethod
    def deserialize_date(attr):
        """Deserialize ISO-8601 formatted string into Date object.

        :param str attr: response string to be deserialized.
        :rtype: Date
        :raises: DeserializationError if string format invalid.
        """
        return isodate.parse_date(attr)

    @staticmethod
    def deserialize_rfc(attr):
        """Deserialize RFC-1123 formatted string into Datetime object.

        :param str attr: response string to be deserialized.
        :rtype: Datetime
        :raises: DeserializationError if string format invalid.
        """
        try:
            date_obj = datetime.datetime.strptime(
                attr, "%a, %d %b %Y %H:%M:%S %Z")
            if not date_obj.tzinfo:
                date_obj = date_obj.replace(tzinfo=TZ_UTC)
        except ValueError as err:
            msg = "Cannot deserialize to rfc datetime object."
            raise_with_traceback(DeserializationError, msg, err)
        else:
            return date_obj

    @staticmethod
    def deserialize_iso(attr):
        """Deserialize ISO-8601 formatted string into Datetime object.

        :param str attr: response string to be deserialized.
        :rtype: Datetime
        :raises: DeserializationError if string format invalid.
        """
        try:
            attr = attr.upper()
            match = Deserializer.valid_date.match(attr)
            if not match:
                raise ValueError("Invalid datetime string: " + attr)

            check_decimal = attr.split('.')
            if len(check_decimal) > 1:
                decimal_str = ""
                for digit in check_decimal[1]:
                    if digit.isdigit():
                        decimal_str += digit
                    else:
                        break
                if len(decimal_str) > 6:
                    attr = attr.replace(decimal_str, decimal_str[0:-1])

            date_obj = isodate.parse_datetime(attr)
            test_utc = date_obj.utctimetuple()
            if test_utc.tm_year > 9999 or test_utc.tm_year < 1:
                raise OverflowError("Hit max or min date")
        except(ValueError, OverflowError, AttributeError) as err:
            msg = "Cannot deserialize datetime object."
            raise_with_traceback(DeserializationError, msg, err)
        else:
            return date_obj

    @staticmethod
    def deserialize_unix(attr):
        """Serialize Datetime object into IntTime format.
        This is represented as seconds.

        :param int attr: Object to be serialized.
        :rtype: Datetime
        :raises: DeserializationError if format invalid
        """
        try:
            date_obj = datetime.datetime.fromtimestamp(attr, TZ_UTC)
        except ValueError as err:
            msg = "Cannot deserialize to unix datetime object."
            raise_with_traceback(DeserializationError, msg, err)
        else:
            return date_obj
