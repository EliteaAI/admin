var roleTableFormatters = {
    checkboxFormatter: (value, row, index, field, editMode) => {
        const checked = value ? 'checked' : '';
        const disabled = editMode ? '' : 'disabled';
        if (editMode) {
            return `
                <label
                    class="mb-0 w-100 d-flex align-items-center custom-checkbox">
                    <input
                        onchange="roleTableFormatters.updateCellCbx(this, '${index}', '${field}', '${row.name}')" 
                        ${disabled}
                        ${checked}
                        type="checkbox">
                </label>
            `
        } else {
            if (checked) return `<i class="icon__16x16 icon-checked__circle"></i>`
        }
    },
    updateCellCbx: (el, index, field, rowName) => {
        $(el.closest('table')).bootstrapTable(
            'updateCell',
            { index: +index, field: field, value: el.checked }
        );
        vueVm.registered_components.RolesTable.updateProxyCell(+index, field, el.checked, rowName);
    },
    clearRowFormatter: (value, row, index, roles) => {
        return `
            <button class="btn btn-default btn-xs btn-table btn-icon__xs mr-2"
                data-toggle="tooltip" data-placement="top" title="Clear all checkboxes"
                onclick="roleTableFormatters.clearRow(this, '${index}', '${roles.toString()}', '${row.name}')">
                <i class="icon__16x16 icon-eraser"></i>
            </button>
        `
    },
    clearRow: (el, index, roles, rowName) => {
        const row = {};
        roles.split(',').forEach(role => {
            row[role] = false;
        })
        $(el.closest('table')).bootstrapTable(
            'updateByUniqueId', {
                id: rowName,
                row: row,
            }
        )
        vueVm.registered_components.RolesTable.clearRow(rowName);
    },
    addColumnTableEvent: (modalType, role = null) => {
        vueVm.registered_components.RolesTable.openCreateModal(modalType, role);
    },
    removeColumnTableEvent: (role) => {
        vueVm.registered_components.RolesTable.openConfirmModal(role);
    },
}