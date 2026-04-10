$(document).on("vue_init", () => {

  $("#btn-delete-users").click(function() {
    if (window.confirm("Delete selected users?")) {
      axios.post(auth_users_api_url, {
          action: "delete",
          users: $("#table").bootstrapTable("getSelections"),
        })
        .then(function (response) {
          if (response.data.ok) {
            showNotify("SUCCESS", "Users deleted");
            $("#table").bootstrapTable("refresh", {});
          } else {
            showNotify("ERROR", response.data.error);
          }
        })
        .catch(function (error) {
          showNotify("ERROR", "Error during deletion");
          console.log(error);
        });
    }
  });

  $("#userCreateModal").on("show.bs.modal", function (e) {
    $("#user_name").val("");
    $("#user_email").val("");
  });

  $("#create_submit").click(function() {
    var user_name = $("#user_name").val();
    var user_email = $("#user_email").val();
    //
    axios.post(auth_users_api_url, {
        action: "create",
        user_name: user_name,
        user_email: user_email,
      })
      .then(function (response) {
        if (response.data.ok) {
          showNotify("SUCCESS", "User created");
          $("#userCreateModal").modal("hide");
          $("#table").bootstrapTable("refresh", {});
        } else {
          showNotify("ERROR", response.data.error);
        }
      })
      .catch(function (error) {
        showNotify("ERROR", "Error during creation");
        console.log(error);
      });
  });

});
