#!/usr/bin/python3
# coding=utf-8

#   Copyright 2026 EPAM Systems
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

""" Missing-table planning and schema scope checks for create_tables (#7548) """

from sqlalchemy import inspect  # pylint: disable=E0401
from sqlalchemy.dialects.postgresql.named_types import CreateEnumType  # pylint: disable=E0401
from sqlalchemy.engine import create_mock_engine  # pylint: disable=E0401
from sqlalchemy.schema import CreateSequence  # pylint: disable=E0401


def plan_missing_tables(connection, metadata):
    """ Tables of the metadata that create_all would create on this connection """
    inspector = inspect(connection)
    return [
        table for table in metadata.sorted_tables
        if not inspector.has_table(table.name, schema=connection.schema_for_object(table))
    ]


def _capture_ddl(connection, metadata, planned):
    """ DDL elements create_all would emit for the planned tables, without running them """
    captured = []
    mock_engine = create_mock_engine(
        connection.engine.url,
        lambda ddl, *args, **kwargs: captured.append(ddl),
    )
    metadata.create_all(mock_engine, tables=planned, checkfirst=False)
    return captured


def _is_already_created(connection, ddl, schema):
    """ Whether the apply's own checkfirst would skip this type or sequence """
    if isinstance(ddl, CreateEnumType):
        return connection.dialect.has_type(connection, ddl.element.name, schema=schema)
    if isinstance(ddl, CreateSequence):
        return connection.dialect.has_sequence(connection, ddl.element.name, schema=schema)
    return False


def find_ddl_outside_schema(connection, metadata, planned, target_schema):
    """ (ddl kind, object name, schema) of each object the apply would create outside target_schema """
    outside = []
    for ddl in _capture_ddl(connection, metadata, planned):
        if not hasattr(ddl, "element"):
            continue
        target = getattr(ddl.element, "table", ddl.element)
        schema = connection.schema_for_object(target)
        landing_schema = schema or connection.dialect.default_schema_name
        if landing_schema == target_schema:
            continue
        if _is_already_created(connection, ddl, schema):
            continue
        found = (type(ddl).__name__, getattr(ddl.element, "name", None), landing_schema)
        if found not in outside:
            outside.append(found)
    return outside
