const RolesTable = {
    props: ['instance_name', 'modes'],
    components: {
        'roles-modal-create': RolesModalCreate,
        'roles-modal-confirm': RolesModalConfirm,
    },
    data() {
        return {
            table_attributes: {
                'data-pagination': 'true',
                'data-side-pagination': 'client',
                'data-unique-id': "name",
                'id': 'roles-table',
                "data-search-selector": "#customSearch"
            },
            roles: null,
            permissions: null,
            tableColumns: null,
            tableData: null,
            editableTableColumns: null,
            editableTableData: null,
            editableRoles: null,
            canEdit: false,
            defaultRole: ['admin', 'viewer', 'editor'],
            newColumnName: null,
            showCreateModal: false,
            showConfirmModal: false,
            modalType: 'create',
            editableRoleName: null,
            deletingRole: null,
            loading: false,
            selectedMode: 'default',
            hasRowError: false,
            url_prefix: window.url_prefix,
        }
    },
    mounted() {

        $('#searchRole').on('input', function ({target: {value}}) {
            $('#roles-table').bootstrapTable('filterBy', {
                name: value.toLowerCase()
            }, {
                'filterAlgorithm': (row, filters) => {
                    const name = filters ? filters.name : '';
                    return row.name.includes(name);
                }
            })
        })
        $('#roles-table').on('page-change.bs.table', (e, data) => {
            if (this.hasRowError) {
                const emptyRowIdxs = this.getEmptyRows();
                if (emptyRowIdxs.length > 0) {
                    this.$nextTick(() => {
                        emptyRowIdxs.forEach(idx => {
                            $('#roles-table').find(`[data-uniqueid='${idx}']`).addClass('empty-row__error');
                        })
                    })
                }
            }
        });
        $('#roles-table').on('sort.bs.table', (e, data) => {
            if(this.hasRowError) {
                const emptyRowIdxs = this.getEmptyRows();
                if (emptyRowIdxs.length > 0) {
                    this.$nextTick(() => {
                        emptyRowIdxs.forEach(idx => {
                            $('#roles-table').find(`[data-uniqueid='${idx}']`).addClass('empty-row__error');
                        })
                    })
                }
            }
        })
        $(document).on('vue_init', () => {
            this.fetchTableData();
        })
    },
    methods: {
        fetchTableData() {
            Promise.all([fetchPermissionsAPI(this.selectedMode), fetchRolesAPI(this.selectedMode)]).then(data => {
                this.roles = data[1].map(role => role.name);
                this.permissions = data[0].rows;
                this.generateTableOptions()
            })
        },
        generateTableOptions() {
            $('#roles-table').bootstrapTable('destroy').bootstrapTable({
                data: this.permissions,
                columns: this.generateColumns(this.roles, false),
                fixedColumns: true,
                fixedNumber: 1,
                undefinedText: '',
            })
        },
        refreshEditableTable() {
            $('#roles-table').bootstrapTable('refreshOptions', {
                undefinedText: '',
                data: this.editableTableData,
                columns: this.editableTableColumns,
                fixedColumns: true,
                fixedNumber: 1,
                fixedRightNumber: 2,
            })
        },
        generateColumns(roles, canEdit) {
            return [
                {
                    field: 'name',
                    title: 'Permission',
                    sortable: true,
                    searchable: true,
                    class: 'min-w-175',
                },
                ...roles.map(role => ({
                    field: role,
                    title: canEdit && !this.defaultRole.includes(role)
                        ? `<span class="d-flex align-items-center cursor-pointer">
                            ${role}<i class="icon__18x18 icon-edit ml-2 d-none" onclick="roleTableFormatters.addColumnTableEvent('edit', '${role}')"></i>
                            <i class="icon__18x18 icon-delete ml-1 d-none" onclick="roleTableFormatters.removeColumnTableEvent('${role}')"></i>
                            </span>`
                        : role,
                    formatter: (value, row, index, field) => roleTableFormatters.checkboxFormatter(value, row, index, field, canEdit),
                    editable: false,
                    class: 'min-w-175',
                }))
            ]
        },
        changeMode() {
            this.canEdit = !this.canEdit;
            if (this.canEdit) {
                this.generateEditableTableOptions();
                this.editableRoles = [...this.roles]
            } else {
                this.fetchTableData();
            }
        },
        generateEditableTableOptions() {
            this.editableTableColumns = [...this.generateColumns(this.roles, true), {
                title: `<span class="d-flex align-items-center cursor-pointer" onclick="roleTableFormatters.addColumnTableEvent('create')">
                        <i class="icon__14x14 icon-add-column mr-1"></i>Add role
                        </span>`,
                class: 'w-28',
            },
                {
                    class: 'w-12',
                    formatter: (value, row, index) => roleTableFormatters.clearRowFormatter(value, row, index, this.roles),
                }];
            this.editableTableData = [...this.permissions]
            if (this.canEdit) {
                this.refreshEditableTable()
            } else {
                this.generateTableOptions();
            }
        },
        clearRow(rowName) {
            this.editableTableData = this.editableTableData.map(row => {
                if (row.name === rowName) {
                    const obj = {};
                    for (const role in row) {
                        if (role === 'name') {
                            obj.name = row[role]
                        } else {
                            obj[role] = false;
                        }
                    }
                    return obj
                }
                return row
            })
        },
        addColumn(newRoleName) {
            this.editableRoles = [...this.editableRoles, newRoleName]
            this.editableTableColumns = [
                ...this.editableTableColumns.slice(0, -2),
                {
                    field: newRoleName,
                    title: `<span class="d-flex align-items-center cursor-pointer">
                            ${newRoleName}<i class="icon__18x18 icon-edit ml-2 d-none" onclick="roleTableFormatters.addColumnTableEvent('edit', '${newRoleName}')"></i>
                            <i class="icon__18x18 icon-delete ml-1 d-none" onclick="roleTableFormatters.removeColumnTableEvent('${newRoleName}')"></i>
                            </span>`,
                    formatter: (value, row, index, field) => roleTableFormatters.checkboxFormatter(value, row, index, field, true),
                    class: 'min-w-175',
                },
                {
                    title: `<span class="d-flex align-items-center cursor-pointer" onclick="roleTableFormatters.addColumnTableEvent('create')">
                        <i class="icon__14x14 icon-add-column mr-1"></i>Add role
                        </span>`,
                    class: 'w-28'
                },
                {
                    class: 'w-12',
                    formatter: (value, row, index) => roleTableFormatters.clearRowFormatter(value, row, index, this.editableRoles),
                }
            ]
            this.editableTableData = this.editableTableData.map(permission => ({
                ...permission,
                [newRoleName]: false,
            }));
            this.refreshEditableTable()
            const tableWidth = document.querySelector(".fixed-table-body").clientWidth
            document.querySelector(".fixed-table-body").scrollLeft = tableWidth;
        },
        updateColumn(newRoleName, currentRoleName) {
            this.editableRoles = [...this.editableRoles.filter(role => role !== currentRoleName), newRoleName];
            this.editableTableColumns = this.editableTableColumns.map(col => {
                if (col.field === currentRoleName) {
                    col.field = newRoleName;
                    col.title = `<span class="d-flex align-items-center cursor-pointer">
                            ${newRoleName}<i class="icon__18x18 icon-edit ml-2 d-none" onclick="roleTableFormatters.addColumnTableEvent('edit', '${newRoleName}')"></i>
                            <i class="icon__18x18 icon-delete ml-1 d-none" onclick="roleTableFormatters.removeColumnTableEvent('${newRoleName}')"></i>
                            </span>`
                }
                return col;
            })
            this.editableTableData.forEach(permission => {
                delete Object.assign(permission, {[newRoleName]: permission[currentRoleName]})[currentRoleName];
            })
            this.refreshEditableTable()
        },
        async handleSaveColumn(newRoleName) {
            this.showCreateModal = false;
            await createRoleAPI(newRoleName, this.selectedMode);
            this.addColumn(newRoleName);
        },
        async handleUpdateColumn(newRoleName) {
            this.showCreateModal = false;
            await updateRoleNameAPI(this.editableRoleName, newRoleName, this.selectedMode);
            this.updateColumn(newRoleName, this.editableRoleName);
        },
        openCreateModal(modalType, role) {
            this.editableRoleName = role;
            this.modalType = modalType;
            this.showCreateModal = true;
        },
        openConfirmModal(role) {
            this.deletingRole = role;
            this.showConfirmModal = true;
        },
        async handleDeleteRole() {
            this.showConfirmModal = false;
            await deleteRoleAPI(this.deletingRole, this.selectedMode);
            this.editableRoles = this.editableRoles.filter(role => role !== this.deletingRole)
            const deletedIndex = this.editableTableColumns.findIndex((col, index) => col.field === this.deletingRole);
            this.editableTableColumns = [
                ...this.editableTableColumns.slice(0, deletedIndex),
                ...this.editableTableColumns.slice(deletedIndex + 1),
            ]
            this.editableTableData = this.editableTableData.map(permission => {
                delete permission[this.deletingRole];
                return permission;
            })
            this.deletingRole = null;
            this.refreshEditableTable()
        },
        updateProxyCell(index, field, checked, rowName) {
            this.editableTableData = this.editableTableData.map(row => {
                if (row.name === rowName) {
                    return {...row, [field]: checked}
                }
                return row
            })
        },
        async saveRoles() {
            const isRowValid = this.rowValidation();
            if (!isRowValid) return;
            saveRolesPermissionsAPI(this.editableTableData, this.selectedMode).then((res) => {
                if (res.ok) {
                    showNotify('SUCCESS', 'Permissions updated')
                    this.canEdit = false;
                    this.fetchTableData();
                    $('#searchRole').val('');
                    $('#roles-table').bootstrapTable('filterBy', {});
                }
            }).catch(e => {
                showNotify('ERROR', e)
            }).finally(() => {
                this.loading = false;
            })
        },
        rowValidation() {
            const emptyRowIds = this.getEmptyRows();
            if (emptyRowIds.length > 0) {
                emptyRowIds.forEach(idx => {
                    $('#roles-table').find(`[data-uniqueid='${idx}']`).addClass('empty-row__error');
                })
                this.hasRowError = true;
                showNotify('ERROR', '[Permission] must be assigned to at least one role.');
                return false;
            }
            this.hasRowError = false;
            return true;
        },
        getEmptyRows() {
            const emptyRowIdx = [];
            this.editableTableData.forEach((row, index) => {
                const rowRoles = Object.assign({}, row);
                const uniqId = rowRoles.name;
                delete rowRoles.name;
                const isFilledRow = Object.values(rowRoles).some(role => role);
                if (!isFilledRow) emptyRowIdx.push(uniqId);
            })
            return emptyRowIdx;
        }
    },
    watch: {
        selectedMode: function (newVal, oldVal) {
            this.fetchTableData();
        }
    },
    template: `
    <div class="">
        <div class="m-3">
            <TableCard
                ref="roles_table"
                header='Roles'
                :table_attributes="table_attributes"
                :events="events"
                :adaptive-height="true"
                >
                <template #actions="{master}">
                    <div class="d-flex justify-content-end">
                        <TextToggle
                            v-if="$root.mode === 'administration'"
                            @register="$root.register"
                            :instance_name="input_instance_name"
                            :labels="modes"
                            v-model="selectedMode"
                        ></TextToggle>

                        <div class="custom-input custom-input_search custom-input_search__sm position-relative ml-2 mr-2">
                            <input type="text" placeholder="Search permissions" id="searchRole">
                            <img src="${url_prefix}/design-system/static/assets/ico/search.svg" class="icon-search position-absolute">
                        </div>
                        <button v-show="!canEdit" type="button" class="btn btn-secondary btn-icon btn-icon__purple mr-2"
                            data-toggle="tooltip" data-placement="top" title="Edit roles"
                            @click="changeMode">
                            <i class="icon__18x18 icon-edit"></i>
                        </button>
                        <template v-if="canEdit">
                            <button type="button" @click="changeMode"
                                id="project_submit" class="btn btn-secondary btn-basic">Cancel</button>
                            <button type="button" @click="saveRoles" class="btn btn-basic d-flex align-items-center ml-2">Save
                                <i v-if="loading" class="preview-loader__white ml-2"></i>
                            </button>
                        </template>
                    </div>
                </template>
            </TableCard>
            <Transition>
                <roles-modal-create
                    v-if="showCreateModal"
                    @close-create-modal="showCreateModal = false"
                    @save-column="handleSaveColumn"
                    @update-column="handleUpdateColumn"
                    :modal-type="modalType"
                    :editable-roles="editableRoles">
                </roles-modal-create>
            </Transition>
            <Transition>
                <roles-modal-confirm
                    v-if="showConfirmModal"
                    @close-confirm="showConfirmModal = false"
                    @delete-role="handleDeleteRole"
                    :editable-roles="editableRoles">
                </roles-modal-confirm>
            </Transition>
        </div>
    </div>
   `
}

register_component('roles-table', RolesTable);
