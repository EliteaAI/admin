$("#btn-add-user-project-defaults").click(function() {
  $("#textarea-logs").val("");
  //
  axios.post(migration_permissions_api_url, {
      mode: "add_user_project_defaults",
      concurrent_tasks: $("#concurrent-tasks").val(),
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

$("#btn-add-team-project-defaults").click(function() {
  $("#textarea-logs").val("");
  //
  axios.post(migration_permissions_api_url, {
      mode: "add_team_project_defaults",
      concurrent_tasks: $("#concurrent-tasks").val(),
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

$("#btn-add-public-project-defaults").click(function() {
  $("#textarea-logs").val("");
  //
  axios.post(migration_permissions_api_url, {
      mode: "add_public_project_defaults",
      concurrent_tasks: $("#concurrent-tasks").val(),
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

$("#btn-add-user-project-permissions").click(function() {
  $("#textarea-logs").val("");
  //
  axios.post(migration_permissions_api_url, {
      mode: "add_user_project_permissions",
      permissions: $("#textarea-permissions").val(),
      concurrent_tasks: $("#concurrent-tasks").val(),
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

$("#btn-add-team-project-permissions").click(function() {
  $("#textarea-logs").val("");
  //
  axios.post(migration_permissions_api_url, {
      mode: "add_team_project_permissions",
      permissions: $("#textarea-permissions").val(),
      concurrent_tasks: $("#concurrent-tasks").val(),
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

$("#btn-add-public-project-permissions").click(function() {
  $("#textarea-logs").val("");
  //
  axios.post(migration_permissions_api_url, {
      mode: "add_public_project_permissions",
      permissions: $("#textarea-permissions").val(),
      concurrent_tasks: $("#concurrent-tasks").val(),
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

$("#btn-delete-user-project-permissions").click(function() {
  $("#textarea-logs").val("");
  //
  axios.post(migration_permissions_api_url, {
      mode: "delete_user_project_permissions",
      permissions: $("#textarea-permissions").val(),
      concurrent_tasks: $("#concurrent-tasks").val(),
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

$("#btn-delete-team-project-permissions").click(function() {
  $("#textarea-logs").val("");
  //
  axios.post(migration_permissions_api_url, {
      mode: "delete_team_project_permissions",
      permissions: $("#textarea-permissions").val(),
      concurrent_tasks: $("#concurrent-tasks").val(),
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

$("#btn-delete-public-project-permissions").click(function() {
  $("#textarea-logs").val("");
  //
  axios.post(migration_permissions_api_url, {
      mode: "delete_public_project_permissions",
      permissions: $("#textarea-permissions").val(),
      concurrent_tasks: $("#concurrent-tasks").val(),
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
