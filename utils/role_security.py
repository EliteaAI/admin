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

""" Role security utilities """

from ..constants import RESTRICTED_ROLES


def filter_restricted_roles(roles):
    """
    Filter out restricted roles from a list of role objects or strings.

    Args:
        roles: List of role dicts (with 'name' key) or role name strings

    Returns:
        Filtered list with restricted roles removed
    """
    if not roles:
        return roles

    if isinstance(roles[0], dict):
        return [r for r in roles if r.get('name') not in RESTRICTED_ROLES]
    else:
        return [r for r in roles if r not in RESTRICTED_ROLES]


def validate_role_assignment(role_names):
    """
    Validate that roles being assigned do not include restricted roles.

    Args:
        role_names: List of role names to validate

    Returns:
        tuple: (is_valid: bool, invalid_roles: set)
    """
    if not role_names:
        return True, set()

    invalid_roles = set(role_names) & RESTRICTED_ROLES
    return len(invalid_roles) == 0, invalid_roles


def get_role_validation_error(invalid_roles):
    """
    Generate a standardized error response for invalid role assignment.

    Args:
        invalid_roles: Set of invalid role names

    Returns:
        tuple: (error_dict, status_code)
    """
    return {
        'msg': f'Cannot assign restricted roles: {", ".join(sorted(invalid_roles))}'
    }, 403
