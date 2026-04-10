const fetchPermissionsAPI = selectedMode => {
    const api_url = V.build_api_url('admin', 'permissions')
    return fetch(
        `${api_url}/${(V.mode === 'administration' ? `${selectedMode}` : `${V.project_id}`)}/`
    ).then((data) => {
        return data.json()
    })
}
const fetchRolesAPI = (selectedMode) => {
    const api_url = V.build_api_url('admin', 'roles')
    return fetch(
        `${api_url}/${(V.mode === 'administration' ? `${selectedMode}` : `${V.project_id}`)}/`
    ).then((data) => {
        return data.json()
    })
}
const saveRolesPermissionsAPI = async (tableData, selectedMode) => {
    const api_url = V.build_api_url('admin', 'permissions')
    const res = await fetch(
        `${api_url}/${(V.mode === 'administration' ? `${selectedMode}` : `${V.project_id}`)}/`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(tableData)
        })
    return res.json();
}
const createRoleAPI = async (newRoleName, selectedMode) => {
    const api_url = V.build_api_url('admin', 'roles')
    const res = await fetch(
        `${api_url}/${(V.mode === 'administration' ? `${selectedMode}` : `${V.project_id}`)}/`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({name: newRoleName})
        })
    return res.json();
}
const deleteRoleAPI = async (roleName, selectedMode) => {
    const api_url = V.build_api_url('admin', 'roles')
    const res = await fetch(
        `${api_url}/${(V.mode === 'administration' ? `${selectedMode}` : `${V.project_id}`)}/`
        , {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({name: roleName})
        })
    return res.json();
}
const updateRoleNameAPI = async (oldRoleName, newRoleName, selectedMode) => {
    const api_url = V.build_api_url('admin', 'roles')
    const res = await fetch(
        `${api_url}/${(V.mode === 'administration' ? `${selectedMode}` : `${V.project_id}`)}/`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({name: oldRoleName, new_name: newRoleName})
        })
    return res.json();
}