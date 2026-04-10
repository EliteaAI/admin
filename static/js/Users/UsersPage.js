const UsersPage = {
    props: ['instance_name'],
    components: {
        'users-modal-confirm': UsersModalConfirm,
    },
    data() {
        return {
            table_attributes: {
                'data-pagination': 'true',
                'data-side-pagination': 'client',
                'data-unique-id': "id",
                'id': 'usersTable',
                'data-page-list': '[5, 10, 15, 20]',
                'data-page-size': 5,
                'data-pagination-parts': ['pageInfo', 'pageList', 'pageSize'],
            },
            loadingApply: false,
            isValidFilter: false,
            applyClicked: false,
            newUser: {
                email: '',
                roles: [],
            },
            selectedRoles: [],
            tableColumns: null,
            tableData: null,
            allExistedRoles: [],
            selectedRows: [],
            showConfirmModal: false,
            loadingDelete: false,
            needRedraw: false,
            url_prefix: window.url_prefix,
        }
    },
    watch: {
        newUser: {
            handler: function (newVal, oldVal) {
                this.isValidFilter = !!newVal.email && !!newVal.roles.length;
            },
            deep: true
        }
    },
    computed: {
        canRemove() {
            return this.selectedRows.length > 0;
        }
    },
    mounted() {
        $(document).on('vue_init', this.fetchUsers)
    },
    methods: {
        fetchUsers() {
            Promise.all([fetchUsersAPI(), fetchRolesAPI('default')]).then(data => {
                this.tableData = data[0].rows;
                this.allExistedRoles = data[1].map(role => role.name);
                this.setTableEvents();
                this.setSearchEvent();
                this.generateTableOptions();
            })
        },
        setTableEvents() {
            const usersTable = $('#usersTable')
            usersTable.on('check.bs.table', (row, $element) => {
                this.getSelection();
            });
            usersTable.on('uncheck.bs.table', (row, $element) => {
                this.getSelection();
            });
            usersTable.on('uncheck-all.bs.table', (row, $element) => {
                this.getSelection();
            });
            usersTable.on('check-all.bs.table', (rowsAfter, rowsBefore) => {
                this.getSelection();
            });
        },
        setSearchEvent() {
            $('#searchUser').on('input', function ({target: {value}}) {
                $('#usersTable').bootstrapTable('filterBy', {
                    name: value.toLowerCase()
                }, {
                    'filterAlgorithm': (row, filters) => {
                        const name = filters ? filters.name : '';
                        return row.email.includes(name);
                    }
                })
            })
        },
        getSelection() {
            this.selectedRows = $('#usersTable').bootstrapTable('getSelections');
        },
        generateColumns() {
            return [
                {
                    checkbox: true,
                },
                {
                    field: 'name',
                    title: 'name',
                    sortable: true,
                    class: 'min-w-175',
                },
                {
                    field: 'email',
                    title: 'email',
                    sortable: true,
                    class: 'min-w-175',
                },
                {
                    field: 'last_login',
                    title: 'last login',
                    sortable: true,
                    class: 'min-w-175',
                    formatter: (value, row, index, field) => value && new Date(value + 'Z').toLocaleString(),
                },
                {
                    field: 'role',
                    title: 'role',
                    class: 'max-w-175 role-cell',
                    formatter: (value, row, index, field) => userTableFormatters.selectRoleFormatter(value, row, index, field, this.allExistedRoles),
                },
                {
                    class: 'w-12',
                    formatter: (value, row, index, field) => userTableFormatters.action(value, row, index, field),
                    events: userTableFormatters.action_events,
                },
            ]
        },
        generateTableOptions() {
            $('#usersTable').bootstrapTable('destroy').bootstrapTable({
                data: this.tableData,
                columns: this.generateColumns(),
                undefinedText: '',
            });
        },
        inviteUser({ email, roles }) {
            this.loadingApply = true;
            const formattedEmails = email.split(',').map(block => block.trim());
            inviteUserAPI(formattedEmails, roles).then(responses => {
                responses.forEach(res => {
                    if (res.status === 'error') {
                        showNotify('ERROR', res.msg);
                    } else {
                        showNotify('SUCCESS', res.msg);
                    }
                })
                this.newUser.email = '';
                this.newUser.roles = [];
                this.fetchUsers();
                this.applyClicked = false;
                this.needRedraw = true;
                this.isValidFilter = false;
            }).finally(() => {
                this.needRedraw = false;
                setTimeout(() => {
                    this.loadingApply = false;
                }, 500)
            })
        },
        hasError(value) {
            return value.length > 0;
        },
        showError(value) {
            return this.applyClicked ? value.length > 0 : true;
        },
        apply() {
            this.applyClicked = true;
            if (this.isValidFilter) {
                this.inviteUser(this.newUser);
            }
        },
        handleDeleteUser() {
            this.loadingDelete = true;
            const userIds = this.selectedRows.map(user => user.id);
            deleteUserAPI(userIds).then(res => {
                setTimeout(() => {
                    this.removeRows(userIds);
                    showNotify('SUCCESS', 'User deleted')
                    this.showConfirmModal = false;
                    this.loadingDelete = false;
                }, 500)
            })
        },
        removeRows(ids) {
            $('#usersTable').bootstrapTable('remove', {
                field: 'id',
                values: ids
            })
        },
    },
    template: `
        <div class="m-3">
            <TableCard
                header='Users'
                ref="users_table"
                :table_attributes="table_attributes"
                :events="events"
                :adaptive-height="true"
                >
                <template #actions="{master}">
                    <div class="d-flex justify-content-end">
                        <div class="custom-input custom-input_search__sm position-relative mb-3 mr-2" style="">
                            <input id="searchUser" type="text" placeholder="User name or email">
                            <img src="${url_prefix}/design-system/static/assets/ico/search.svg" class="icon-search position-absolute">
                        </div>
                        <button id="removeButton" type="button" :disabled="!canRemove" class="btn btn-secondary btn-icon btn-icon__purple"
                            @click="showConfirmModal = true">
                            <i class="fas fa-trash-alt"></i>
                        </button>
                    </div>
                </template>
                <template #extra="{master}">
                    <div id="newUserBlock" class="d-flex">
                        <div class="mr-2 flex-grow-1 cell-input">
                            <p class="font-h6 font-semibold mb-1">Email Addresses</p>
                            <div class="custom-input custom-input__sm need-validation" :class="{'invalid-input': !showError(newUser.email)}"
                                :data-valid="hasError(newUser.email)">
                                <input
                                    type="text"
                                    v-model="newUser.email"
                                    placeholder="Enter email or emails separated by comma">
                                <span class="input_error-msg">Email is required!</span>
                            </div>
                        </div>
                        <div class="mr-2 cell-input" style="min-width: 250px">
                            <p class="font-h6 font-semibold mb-1">Roles</p>
                            <div class="select-validation need-validation" :class="{'invalid-select': !showError(newUser.roles)}"
                                :data-valid="hasError(newUser.roles)">
                                <multiselect-dropdown
                                    :key="needRedraw"
                                    @register="register"
                                    placeholder="Select role"
                                    container_class="bootstrap-select__b"
                                    v-model:modelValue="newUser.roles"
                                    button_class="btn-select__sm btn btn-select dropdown-toggle d-inline-flex align-items-center"
                                    :list_items="allExistedRoles"
                                    :has_error_class="{'invalid-select': !showError(newUser.roles)}"
                                    instance_name="multiselect_dropdown_1"
                                ></multiselect-dropdown>
                                <span class="select_error-msg">Role is required!</span>
                            </div>
                        </div>
                        <div class="pt-1">
                            <button class="btn btn-basic d-flex align-items-center mt-3"
                                type="button"
                                @click="apply">Invite
                                    <i v-if="loadingApply" class="preview-loader__white ml-2"></i>
                            </button>
                        </div>
                    </div>
                    <div class="d-flex flex-column mx-3 mt-2"><slot name="invitation_integration"></slot></div>
                </template>
            </TableCard>
            <Transition>
                <users-modal-confirm
                    v-if="showConfirmModal"
                    :loadingDelete="loadingDelete"
                    @close-confirm="showConfirmModal = false"
                    @delete="handleDeleteUser">
                </users-modal-confirm>
            </Transition>
        </div>
   `
}
register_component('users-page', UsersPage);
