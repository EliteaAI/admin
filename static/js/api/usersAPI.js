const fetchUsersAPI = async () => {
    const api_url = V.build_api_url('admin', 'users');
    const res = await fetch (`${api_url}/${getSelectedProjectId()}`,{
        method: 'GET',
    });
    return res.json();
}
const updateUserAPI = async (id, roles) => {
    const api_url = V.build_api_url('admin', 'users');
    const res = await fetch (`${api_url}/${getSelectedProjectId()}`,{
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, roles })
    });
    return res;
}

const deleteUserAPI = async (ids) => {
    const params = new URLSearchParams();
    params.append('id[]', ids.join(','));

    const api_url = V.build_api_url('admin', 'users');
    const res = await fetch (`${api_url}/${getSelectedProjectId()}?${params}`,{
        method: 'DELETE',
    });
    return res;
}

const inviteUserAPI = async (formattedEmails, roles) => {
    const api_url = V.build_api_url('admin', 'users');
    const {invitation_integration} = V.custom_data
    const res = await fetch (`${api_url}/${getSelectedProjectId()}`,{
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            "emails": formattedEmails,
            "roles": roles,
            invitation_integration
        })
    });
    return res.json();
}
