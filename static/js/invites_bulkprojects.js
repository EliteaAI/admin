$("#btn-add-user-to-selected").click(function() {
  $("#textarea-logs").val("");
  //
  axios.post(invites_bulkprojects_api_url, {
      user_id: $("#input-user-id").val(),
      roles: $("#input-roles").val(),
      projects: $("#table").bootstrapTable("getSelections"),
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
