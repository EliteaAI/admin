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

""" Authenticated encryption for project backup artifacts

A backup is wrapped in the shared AES-256-GCM envelope (tools.artifact_crypto)
keyed from SECRETS_MASTER_KEY, so it can only be read back on a setup holding
the same master key. Restore therefore accepts platform-produced artifacts
only: a hand-written .sql file carries no valid tag and is refused before a
single statement is parsed.

The magic and HKDF info strings below are part of the on-disk format: changing
them makes every existing backup unreadable.
"""

from tools import artifact_crypto  # pylint: disable=E0401


ENVELOPE_MAGIC = b"ELITEA-BACKUP-ENC/1"
ENVELOPE_SUFFIX = artifact_crypto.ENVELOPE_SUFFIX
ENVELOPE_MIMETYPE = artifact_crypto.ENVELOPE_MIMETYPE

CIPHER = artifact_crypto.CIPHER
KDF = artifact_crypto.KDF

KEY_INFO = b"elitea-project-backup/v1/aes-256-gcm"
KEY_ID_INFO = b"elitea-project-backup/v1/key-id"

FRAME_SIZE = artifact_crypto.FRAME_SIZE
MAX_FRAME_SIZE = artifact_crypto.MAX_FRAME_SIZE

POLICY_DISABLED = artifact_crypto.POLICY_DISABLED
POLICY_ENABLED = artifact_crypto.POLICY_ENABLED
POLICY_REQUIRED = artifact_crypto.POLICY_REQUIRED
POLICIES = artifact_crypto.POLICIES

CONFIG_KEY = "backup_encryption"

BACKUP_ENVELOPE = artifact_crypto.Envelope(ENVELOPE_MAGIC, KEY_INFO, KEY_ID_INFO, "backup")

configured_master_key = artifact_crypto.configured_master_key

key_id = BACKUP_ENVELOPE.key_id
is_encrypted = BACKUP_ENVELOPE.is_encrypted
iter_encrypt = BACKUP_ENVELOPE.iter_encrypt
iter_decrypt = BACKUP_ENVELOPE.iter_decrypt
wrap_decrypt = BACKUP_ENVELOPE.wrap_decrypt


def resolve_policy(config):
    """ Read the encryption policy out of the plugin descriptor config """
    return artifact_crypto.resolve_policy(config, CONFIG_KEY)


def handler_policy(handler):
    """ Encryption policy for an API mode handler """
    module = getattr(handler, "module", None)
    descriptor = getattr(module, "descriptor", None)
    return resolve_policy(getattr(descriptor, "config", None))
