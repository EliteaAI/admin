function userAddSubmit() {
  fetch(window.url_prefix + '/api/v1/admin/users/administration/' + project + '/', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        "emails": [$('#user_name').val()],
        "roles": [$('#user_role').val()]
      })
  }).then(response => {
      $("#userAddModal").modal('hide');
      location.reload();
  })
}

$(document).on('vue_init', () => {
    $('#project_user_submit').on('click', userAddSubmit)
})
