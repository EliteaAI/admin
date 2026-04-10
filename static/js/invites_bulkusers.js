$("#btn-add-all-users").click(function() {
  $("#textarea-logs").val("");
  //
  axios.post(invites_bulkusers_api_url, {
      project_id: $("#input-project-id").val(),
      roles: $("#input-roles").val(),
    })
    .then(function (response) {
      showNotify("SUCCESS", "Action performed")
      $("#textarea-logs").val(response.data.logs);
    })
    .catch(function (error) {
      showNotify("ERROR", "Error during action")
      console.log(error);
    });
});
