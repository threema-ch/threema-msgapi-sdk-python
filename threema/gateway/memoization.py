# Inlined from python-memoization (https://github.com/lonelyenvoy/python-memoization)
#
# -----------
#
# MIT License
#
# Copyright (c) 2018-2020 lonelyenvoy
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import time

__all__ = (
    'HashedList',
    'make_key',
    'make_cache_value',
    'is_cache_value_valid',
    'retrieve_result_from_cache_value',
)


class HashedList(list):
    """
    This class guarantees that hash() will be called no more than once per element.
    """

    __slots__ = ('hash_value', )

    def __init__(self, tup, hash_value):
        super().__init__(tup)
        self.hash_value = hash_value

    def __hash__(self):
        return self.hash_value


def make_key(args, kwargs, kwargs_mark=(object(), )):
    """
    Make a cache key
    """
    key = args
    if kwargs:
        key += kwargs_mark
        for item in kwargs.items():
            key += item
    try:
        hash_value = hash(key)
    except TypeError:  # process unhashable types
        return str(key)
    else:
        return HashedList(key, hash_value)


def make_cache_value(result, ttl):
    return result, time.time() + ttl


def is_cache_value_valid(value):
    return time.time() < value[1]


def retrieve_result_from_cache_value(value):
    return value[0]
