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

""" Project restore: merge the entities of a backup into a project that has content

The rows of every carried table are staged, then copied in with fresh ids,
like the chats (chat_restore): ids of another project collide with the
target's own rows, and ON CONFLICT DO NOTHING would then drop a skill and hang
its versions under the target's skill holding that id.

A row the target already holds (same identity) is not copied: references to it
point at the target's row, and the rows it owns are skipped with it. The
foreign keys come from the catalog; references the catalog does not know
(polymorphic entity ids, ids inside JSON) are declared here.
"""

from pylon.core.tools import log  # pylint: disable=E0611,E0401

from .chat_restore import _quote, _staging_name  # pylint: disable=W0611


# table -> columns a row is recognised by in the target, for tables without a
# uuid. created_at is kept by the backup and never edited, so a restored row
# matches its own earlier copy and not an unrelated one of the same name;
# settings are not part of it because a safe backup redacts their secrets.
IDENTITY_KEYS = {
    "tags": ("name",),
    "elitea_tools": ("type", "name", "created_at"),
    "prompts": ("name", "description", "created_at"),
}

# Matched rows of these are shared, not owned: the backup's tag named like one
# of the target's is that tag, and its associations are still restored
SHARED_TABLES = frozenset(("tags",))

# NOT NULL foreign keys that point at a used entity rather than at the owner:
# an agent version attaching a toolkit or skill the target already holds keeps
# the attachment
NON_OWNER_REFERENCES = frozenset((
    ("entity_tool_mapping", "tool_id"),
    ("entity_skill_mapping", "skill_id"),
    ("entity_skill_mapping", "skill_version_id"),
    ("application_version_tag_association", "tag_id"),
    ("prompt_version_tag_association", "tag_id"),
    ("skill_version_tag_association", "tag_id"),
    ("eval_binding", "dimension_id"),
    ("eval_binding", "code_validation_id"),
    ("eval_binding", "application_version_id"),
))

# (table, column, parent, condition, owner) - id columns without a foreign key.
# condition, when set, is SQL over the row (alias s) telling the column points at parent.
COLUMN_REFERENCES = (
    ("entity_tool_mapping", "entity_id", "applications", "s.entity_type = 'agent'", False),
    ("entity_tool_mapping", "entity_version_id", "application_versions", "s.entity_type = 'agent'", True),
    ("entity_skill_mapping", "entity_version_id", "application_versions", "s.entity_type = 'agent'", True),
    ("prompts", "new_agent_id", "applications", None, False),
    ("prompt_versions", "new_agent_version_id", "application_versions", None, False),
    ("entity_schedules", "legacy_application_id", "applications", None, False),
    ("entity_schedules", "legacy_version_id", "application_versions", None, False),
    ("agent_identity_binding", "application_id", "applications", None, True),
    ("agent_identity_binding", "version_id", "application_versions", None, True),
    ("autonomous_mandate", "application_id", "applications", None, True),
    ("autonomous_mandate", "agent_version", "application_versions", None, False),
    ("autonomous_mandate", "toolkit_id", "elitea_tools", None, False),
    ("credential_use_grant", "application_id", "applications", None, True),
)

# (table, JSON column, key, parent, condition) - top-level keys of a JSON object
# holding the id of another restored row
JSON_REFERENCES = (
    ("elitea_tools", "settings", "application_id", "applications", "s.type = 'application'"),
    ("elitea_tools", "settings", "application_version_id", "application_versions", "s.type = 'application'"),
    ("applications", "meta", "default_version_id", "application_versions", None),
    ("skills", "meta", "default_version_id", "skill_versions", None),
    ("application_versions", "meta", "attachment_toolkit_id", "elitea_tools", None),
)

# Columns naming run state the restore does not carry, or carries under other ids
CLEARED_COLUMNS = {
    "entity_schedules": ("last_conversation_id",),
    "eval_suite": ("baseline_run_id",),
}


def _literal(value):
    return "'{}'".format(str(value).replace("'", "''"))


def foreign_keys(cursor, schema):
    """ [(child, column, parent, not null)] of the single-column foreign keys onto an id """
    cursor.execute(
        "select child.relname, att.attname, parent.relname, att.attnotnull"
        " from pg_constraint con"
        " join pg_class child on child.oid = con.conrelid"
        " join pg_class parent on parent.oid = con.confrelid"
        " join pg_namespace child_ns on child_ns.oid = child.relnamespace"
        " join pg_namespace parent_ns on parent_ns.oid = parent.relnamespace"
        " join pg_attribute att on att.attrelid = con.conrelid and att.attnum = con.conkey[1]"
        " join pg_attribute parent_att"
        " on parent_att.attrelid = con.confrelid and parent_att.attnum = con.confkey[1]"
        " where con.contype = 'f' and array_length(con.conkey, 1) = 1 and parent_att.attname = 'id'"
        " and child_ns.nspname = %s and parent_ns.nspname = %s",
        (schema, schema),
    )
    return [tuple(row) for row in cursor.fetchall()]


def serial_tables(cursor, schema):
    """ Tables whose integer id takes its value from a sequence """
    # The sequence owning the column, as pg_get_serial_sequence finds it, read
    # from pg_depend: the function raises on a table without an id column
    cursor.execute(
        "select distinct c.relname from pg_class c"
        " join pg_namespace n on n.oid = c.relnamespace"
        " join pg_attribute a on a.attrelid = c.oid and a.attname = 'id' and not a.attisdropped"
        " join pg_depend d on d.refobjid = c.oid and d.refobjsubid = a.attnum"
        " and d.classid = 'pg_class'::regclass and d.deptype in ('a', 'i')"
        " join pg_class seq on seq.oid = d.objid and seq.relkind = 'S'"
        " where n.nspname = %s and c.relkind in ('r', 'p')"
        " and a.atttypid in ('integer'::regtype, 'bigint'::regtype, 'smallint'::regtype)",
        (schema,),
    )
    return {row[0] for row in cursor.fetchall()}


class Reference:  # pylint: disable=R0903,R0913
    """ A column (or a key of a JSON column) of `table` holding an id of `parent` """

    def __init__(self, table, column, parent, key=None, condition=None, not_null=False, owner=False):
        self.table = table
        self.column = column
        self.parent = parent
        self.key = key
        self.condition = condition
        self.not_null = not_null
        self.owner = owner

    def value(self, alias="s"):
        """ The referenced id, as bigint """
        if self.key is None:
            return "{}.{}::bigint".format(alias, _quote(self.column))
        return (
            "CASE WHEN jsonb_typeof({a}.{c}::jsonb -> {k}) = 'number'"
            " THEN ({a}.{c}::jsonb ->> {k})::bigint END"
        ).format(a=alias, c=_quote(self.column), k=_literal(self.key))

    def applies(self, alias="s"):
        if not self.condition:
            return "true"
        return "({})".format(self.condition.replace("s.", "{}.".format(alias)))


def references_of(tables, columns_by_table, fk_edges, serial=()):
    """ table -> [Reference] for the staged tables

    A NOT NULL foreign key names the row's owner, unless declared otherwise. Rows
    of a table without an id of its own (tag associations) are owned by every
    row they link, nullable columns included.
    """
    references = {}
    #
    for child, column, parent, not_null in fk_edges:
        if child not in tables or child == parent:
            continue
        references.setdefault(child, []).append(Reference(
            child, column, parent, not_null=not_null,
            owner=(not_null or child not in serial) and (child, column) not in NON_OWNER_REFERENCES,
        ))
    #
    for table, column, parent, condition, owner in COLUMN_REFERENCES:
        if table in tables and parent in tables and column in columns_by_table.get(table, ()):
            references.setdefault(table, []).append(Reference(
                table, column, parent, condition=condition, owner=owner,
            ))
    #
    for table, column, key, parent, condition in JSON_REFERENCES:
        if table in tables and parent in tables and column in columns_by_table.get(table, ()):
            references.setdefault(table, []).append(Reference(
                table, column, parent, key=key, condition=condition,
            ))
    #
    return references


def copy_order(tables, references):
    """ Tables with their parents first

    Column references must be resolved before a table is copied; JSON ones are
    preferred but may be fixed up afterwards (an agent's meta names its default
    version, which references the agent). When nothing is fully ready, the table
    with the fewest unresolved JSON references goes next.
    """
    hard = {table: set() for table in tables}
    soft = {table: set() for table in tables}
    for table, items in references.items():
        for item in items:
            if item.parent in tables and item.parent != table:
                (soft if item.key is not None else hard)[table].add(item.parent)
    #
    ordered, done = [], set()
    pending = sorted(tables)
    while pending:
        ready = [table for table in pending if hard[table] <= done and soft[table] <= done]
        if not ready:
            candidates = [table for table in pending if hard[table] <= done] or pending
            ready = [min(candidates, key=lambda table: (len(soft[table] - done), table))]
        ordered.extend(ready)
        done.update(ready)
        pending = [table for table in pending if table not in done]
    return ordered


def identity_key(table, columns):
    if table in IDENTITY_KEYS:
        key = IDENTITY_KEYS[table]
        return list(key) if all(name in columns for name in key) else None
    return ["uuid"] if "uuid" in columns else None


def _same(columns, types, left, right):
    parts = []
    for name in columns:
        if name == "uuid":
            # Indexed in the target: plain equality lets the planner use it
            parts.append("{l}.{c} = {r}.{c}".format(l=left, r=right, c=_quote(name)))
        elif types.get(name) in ("json", "jsonb"):
            parts.append("{l}.{c}::jsonb IS NOT DISTINCT FROM {r}.{c}::jsonb".format(l=left, r=right, c=_quote(name)))
        else:
            parts.append("{l}.{c} IS NOT DISTINCT FROM {r}.{c}".format(l=left, r=right, c=_quote(name)))
    return " AND ".join(parts) or "true"


class EntityMerge:  # pylint: disable=R0902
    """ Copies the staged entity rows into the target with fresh ids """

    def __init__(self, cursor, staged, columns_by_table, types_by_table, fk_edges, serial,  # pylint: disable=R0913
                 cross_project=False):
        self.cursor = cursor
        # The backup's ids belong to another project: one that was not restored
        # names nothing in the target, whatever row holds it there
        self.cross_project = cross_project
        self.staged = staged
        self.columns_by_table = columns_by_table
        self.types_by_table = types_by_table
        self.tables = set(staged)
        self.serial = set(serial) & self.tables
        self.references = references_of(self.tables, columns_by_table, fk_edges, self.serial)
        self.maps = {}
        self.deferred = []
        self.summary = {}

    def _execute(self, sql):
        self.cursor.execute(sql)
        return max(self.cursor.rowcount or 0, 0)

    def _mapped(self, item, alias="s"):
        """ SQL: whether the referenced row is in the parent's map, and its new id there """
        mapping = self.maps[item.parent]
        exists = "EXISTS (SELECT 1 FROM {m} m WHERE m.old_id = {v})".format(m=mapping, v=item.value(alias))
        new_id = "(SELECT m.new_id FROM {m} m WHERE m.old_id = {v})".format(m=mapping, v=item.value(alias))
        return exists, new_id

    def _remapped(self, table, where=None):
        """ A temp copy of the staged rows (those matching `where`) with the references
            resolved so far rewritten """
        columns = sorted(self.columns_by_table[table])
        types = self.types_by_table.get(table, {})
        expressions = {name: "s.{}".format(_quote(name)) for name in columns}
        json_items = {}
        #
        for item in self.references.get(table, ()):
            if item.parent not in self.maps:
                if item.key is not None and item.parent in self.serial:
                    self.deferred.append(item)
                elif item.key is None and self.cross_project and item.parent not in self.tables:
                    # A partial restore left the parent out: the id names no row of the target
                    expressions[item.column] = "CASE WHEN {a} THEN NULL ELSE s.{c} END".format(
                        a=item.applies(), c=_quote(item.column))
                continue
            if item.key is not None:
                json_items.setdefault(item.column, []).append(item)
                continue
            _, new_id = self._mapped(item)
            # A referenced row of the backup goes where it went. One the restore did not
            # copy (dropped, or skipped with its owner) has no row: NULL, so the row is
            # dropped or the reference cleared, never left on the target's row holding the id
            expressions[item.column] = "CASE WHEN {a} THEN {n} ELSE s.{c} END".format(
                a=item.applies(), n=new_id, c=_quote(item.column))
        #
        for column, items in json_items.items():
            expression = "s.{}::jsonb".format(_quote(column))
            for item in items:
                expression = self._json_rewrite(expression, item, "s")
            expressions[column] = "({})::{}".format(expression, types.get(column, "jsonb"))
        #
        for column in CLEARED_COLUMNS.get(table, ()):
            if column in expressions:
                expressions[column] = "NULL"
        #
        remapped = _staging_name(table, "_remapped")
        self._execute("DROP TABLE IF EXISTS {}".format(remapped))
        self._execute("CREATE TEMP TABLE {} ON COMMIT DROP AS SELECT {} FROM {} s{}".format(
            remapped, ", ".join("{} AS {}".format(expressions[name], _quote(name)) for name in columns),
            self.staged[table], " WHERE NOT ({})".format(where) if where else "",
        ))
        return remapped, columns

    def _json_rewrite(self, expression, item, alias):
        exists, new_id = self._mapped(item, alias)
        # Same project: an id the backup does not map is one of the project's own rows
        mapped = "true" if self.cross_project else exists
        return (
            "CASE WHEN {a} AND jsonb_typeof({e}) = 'object' AND {e} ? {k} AND {x} THEN"
            " CASE WHEN {n} IS NULL THEN {e} - {k} ELSE jsonb_set({e}, ARRAY[{k}], to_jsonb({n})) END"
            " ELSE {e} END"
        ).format(a=item.applies(alias), e=expression, x=mapped, n=new_id, k=_literal(item.key))

    def _owner_skipped(self, table):
        """ SQL over a staged row (alias s, original values): it hangs under a row
            the restore does not copy (Q2: an entity already present is skipped with
            everything it owns) """
        conditions = [
            "({a} AND EXISTS (SELECT 1 FROM {m} o WHERE o.old_id = {v} AND o.skipped))".format(
                a=item.applies(), m=self.maps[item.parent], v=item.value(),
            )
            for item in self.references.get(table, ())
            if item.owner and item.key is None and item.parent in self.maps
        ]
        return " OR ".join(conditions)

    def _drop_dangling(self, table, source):
        """ Drop rows whose required parent the target does not have, clear optional
            references to such rows; return the dropped count """
        dropped = 0
        for item in self.references.get(table, ()):
            if item.key is not None:
                continue
            missing = "{a} AND s.{c} IS NOT NULL AND NOT EXISTS (SELECT 1 FROM {p} p WHERE p.id = s.{c}::bigint)".format(
                a=item.applies(), c=_quote(item.column), p=_quote(item.parent))
            if item.not_null or item.owner or item.condition:
                # Pointed at a row of the backup that was not copied: cleared by _remapped
                dropped += self._execute("DELETE FROM {} s WHERE {} AND s.{} IS NULL".format(
                    source, item.applies(), _quote(item.column)))
            if item.not_null or item.owner or item.condition:
                dropped += self._execute("DELETE FROM {} s WHERE {}".format(source, missing))
            else:
                self._execute("UPDATE {} s SET {} = NULL WHERE {}".format(source, _quote(item.column), missing))
        if dropped:
            log.warning(
                "entity_restore: %s rows of %s reference rows the target does not have; skipping them",
                dropped, table,
            )
        return dropped

    def _merge_table(self, table):  # pylint: disable=R0914
        types = self.types_by_table.get(table, {})
        key = identity_key(table, self.columns_by_table[table])
        stats = {"restored": 0, "skipped": 0, "orphans": 0}
        #
        # Owner links are evaluated on the original values, against the parents' maps
        owned = self._owner_skipped(table)
        serial = table in self.serial and "id" in self.columns_by_table[table]
        # Without an id of its own, a row skipped with its owner is left out of the copy
        remapped, columns = self._remapped(table, None if serial else owned)
        #
        if serial:
            mapping = _staging_name(table, "_map")
            self._execute(
                "CREATE TEMP TABLE {} (old_id bigint PRIMARY KEY, new_id bigint, skipped boolean NOT NULL)"
                " ON COMMIT DROP".format(mapping)
            )
            if key:
                # Present in the target: references go to the target's row
                matched = self._execute(
                    "INSERT INTO {m} SELECT DISTINCT ON (s.id) s.id, t.id, {skip} FROM {r} s"
                    " JOIN {t} t ON {same} ORDER BY s.id, t.id".format(
                        m=mapping, r=remapped, t=_quote(table), same=_same(key, types, "t", "s"),
                        skip="false" if table in SHARED_TABLES else "true",
                    )
                )
                stats["merged" if table in SHARED_TABLES else "skipped"] = matched
            if owned:
                # Owned by a row that is not copied: dropped with it
                stats["skipped"] += self._execute(
                    "INSERT INTO {m} SELECT DISTINCT s.id, NULL::bigint, true FROM {st} s"
                    " WHERE ({owned}) AND NOT EXISTS (SELECT 1 FROM {m} x WHERE x.old_id = s.id)".format(
                        m=mapping, st=self.staged[table], owned=owned)
                )
            self._execute("DELETE FROM {r} s WHERE EXISTS (SELECT 1 FROM {m} m WHERE m.old_id = s.id)".format(
                r=remapped, m=mapping))
            stats["orphans"] = self._drop_dangling(table, remapped)
            self._execute(
                "INSERT INTO {m} SELECT s.id, nextval(pg_get_serial_sequence({t}, 'id')), false"
                " FROM (SELECT DISTINCT id FROM {r}) s ORDER BY s.id".format(
                    m=mapping, r=remapped, t=_literal(_quote(table)))
            )
            self.maps[table] = mapping
            others = [name for name in columns if name != "id"]
            stats["restored"] = self._execute(
                "INSERT INTO {t} (id{sep}{cols}) SELECT DISTINCT ON (s.id) m.new_id{sep}{src}"
                " FROM {r} s JOIN {m} m ON m.old_id = s.id ORDER BY s.id ON CONFLICT DO NOTHING".format(
                    t=_quote(table), r=remapped, m=mapping, sep=", " if others else "",
                    cols=", ".join(_quote(name) for name in others),
                    src=", ".join("s.{}".format(_quote(name)) for name in others),
                )
            )
            # Refused by another unique constraint (a shared origin the target has)
            refused = self._execute(
                "UPDATE {m} m SET new_id = NULL, skipped = true WHERE NOT m.skipped"
                " AND NOT EXISTS (SELECT 1 FROM {t} t WHERE t.id = m.new_id)".format(m=mapping, t=_quote(table))
            )
            if refused:
                log.warning("entity_restore: %s rows of %s conflict with rows of the target; skipping them",
                            refused, table)
                stats["skipped"] += refused
        else:
            if owned:
                self.cursor.execute("SELECT count(*) FROM {} s WHERE {}".format(self.staged[table], owned))
                stats["skipped"] += self.cursor.fetchone()[0]
            stats["orphans"] = self._drop_dangling(table, remapped)
            if key:
                stats["skipped"] += self._execute(
                    "DELETE FROM {r} s WHERE EXISTS (SELECT 1 FROM {t} t WHERE {same})".format(
                        r=remapped, t=_quote(table), same=_same(key, types, "t", "s")))
            # A row identical to one the target holds (restored before) adds nothing
            stats["restored"] = self._execute(
                "INSERT INTO {t} ({cols}) SELECT DISTINCT {src} FROM {r} s"
                " WHERE NOT EXISTS (SELECT 1 FROM {t} x WHERE {same}) ON CONFLICT DO NOTHING".format(
                    t=_quote(table), r=remapped, cols=", ".join(_quote(name) for name in columns),
                    src=", ".join("s.{}".format(_quote(name)) for name in columns),
                    same=_same(columns, types, "x", "s"),
                )
            )
        #
        self.summary[table] = stats

    def _fix_deferred(self):
        """ JSON references to tables copied later (an agent's default version) """
        for item in self.deferred:
            if item.table not in self.maps or item.parent not in self.maps:
                continue
            column = _quote(item.column)
            expression = self._json_rewrite("t.{}::jsonb".format(column), item, "t")
            self._execute(
                "UPDATE {t} t SET {c} = ({e})::{type} FROM {m} r"
                " WHERE r.new_id = t.id AND NOT r.skipped".format(
                    t=_quote(item.table), c=column, e=expression, m=self.maps[item.table],
                    type=self.types_by_table.get(item.table, {}).get(item.column, "jsonb"),
                )
            )

    def run(self):
        for table in copy_order(self.tables, self.references):
            self._merge_table(table)
        self._fix_deferred()
        return self.summary, dict(self.maps)


def merge_entities(cursor, staged, columns_by_table, types_by_table, fk_edges, serial,  # pylint: disable=R0913
                   cross_project=False):
    """ Copy the staged entity rows into the target, return (summary, maps)

    maps: table -> temp table (old_id, new_id, skipped) for the tables with a serial id;
    new_id is the target's row a reference to old_id now goes to, NULL when there is none
    """
    return EntityMerge(cursor, staged, columns_by_table, types_by_table, fk_edges, serial, cross_project).run()
