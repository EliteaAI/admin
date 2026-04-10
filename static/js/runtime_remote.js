$("#btn-update").click(function() {
  var data = $("#table").bootstrapTable("getSelections");
  //
  axios.post(remote_api_url, {data: data, action: "update"})
    .then(function (response) {
      showNotify("SUCCESS", "Update and restart requested")
    })
    .catch(function (error) {
      showNotify("ERROR", "Error during update and restart request")
      console.log(error);
    });
});


$("#btn-update-with-reqs").click(function() {
  var data = $("#table").bootstrapTable("getSelections");
  //
  axios.post(remote_api_url, {data: data, action: "update_with_reqs"})
    .then(function (response) {
      showNotify("SUCCESS", "Update and restart requested")
    })
    .catch(function (error) {
      showNotify("ERROR", "Error during update and restart request")
      console.log(error);
    });
});


$("#btn-purge-reqs").click(function() {
  var data = $("#table").bootstrapTable("getSelections");
  //
  axios.post(remote_api_url, {data: data, action: "purge_reqs"})
    .then(function (response) {
      showNotify("SUCCESS", "Purge and restart requested")
    })
    .catch(function (error) {
      showNotify("ERROR", "Error during purge and restart request")
      console.log(error);
    });
});


$("#btn-delete").click(function() {
  var data = $("#table").bootstrapTable("getSelections");
  //
  axios.post(remote_api_url, {data: data, action: "delete"})
    .then(function (response) {
      showNotify("SUCCESS", "Deletion and restart requested")
    })
    .catch(function (error) {
      showNotify("ERROR", "Error during deletion and restart request")
      console.log(error);
    });
});


$("#btn-export-configs").click(function() {
  var data = $("#table").bootstrapTable("getSelections");
  //
  $("#form-export-configs-data").val(JSON.stringify(data));
  $("#form-export-configs").submit();
});


$("#btn-reload").click(function() {
  var data = $("#table").bootstrapTable("getSelections");
  //
  axios.post(remote_api_url, {data: data, action: "reload"})
    .then(function (response) {
      showNotify("SUCCESS", "Reload requested")
    })
    .catch(function (error) {
      showNotify("ERROR", "Error during reload request")
      console.log(error);
    });
});


$("#btn-manual").click(function() {
  var data = $("#ipt-manual").val();
  var result = [];
  //
  var pylons_data = data.split(";");
  //
  for (var i_idx in pylons_data) {
    var items = pylons_data[i_idx].split(":");
    //
    var pylon_id = items[0].trim();
    var plugins = items[1].split(",");
    //
    for (var j_idx in plugins) {
      var plugin = plugins[j_idx].trim();
      //
      result.push({
        "pylon_id": pylon_id,
        "name": plugin,
        "state": true,
      });
    }
  }
  //
  axios.post(remote_api_url, {data: result})
    .then(function (response) {
      showNotify("SUCCESS", "Update and restart requested")
    })
    .catch(function (error) {
      showNotify("ERROR", "Error during update and restart request")
      console.log(error);
    });
});


$("#modal-edit-config").on("show.bs.modal", function (e) {
  $("#form-edit-config").get(0).reset();
  $("#modal-edit-plugin").text(edit_config_row.name);
});


$("#btn-cfg-load").click(function() {
  axios.get(remote_edit_api_url + "/" + edit_config_row.pylon_id + ":" + edit_config_row.name)
    .then(function (response) {
      $("#input-cfg-edit").val(response.data.config);
    })
    .catch(function (error) {
      showNotify("ERROR", "Error during config retrieval")
      console.log(error);
    });
});


$("#btn-cfg-load-raw").click(function() {
  axios.get(remote_edit_api_url + "/" + edit_config_row.pylon_id + ":" + edit_config_row.name + "?raw=true")
    .then(function (response) {
      $("#input-cfg-edit").val(response.data.config);
    })
    .catch(function (error) {
      showNotify("ERROR", "Error during config retrieval")
      console.log(error);
    });
});


$("#btn-cfg-save").click(function() {
  var result = $("#input-cfg-edit").val();
  axios.post(remote_edit_api_url + "/" + edit_config_row.pylon_id + ":" + edit_config_row.name, {data: result})
    .then(function (response) {
      showNotify("SUCCESS", "Config save requested")
      $("#modal-edit-config").modal("hide");
    })
    .catch(function (error) {
      showNotify("ERROR", "Error during config save")
      console.log(error);
    });
});


$("#btn-import-configs").click(function() {
  $("#modal-import-config").modal("show");
});


$("#modal-import-config").on("show.bs.modal", function (e) {
  $("#form-import-config").get(0).reset();
});


$("#btn-cfg-import").click(function() {
  var data = new FormData();
  data.append("action", "import_configs");
  data.append("file", $("#input-cfg-import")[0].files[0]);
  //
  axios.post(remote_api_url, data)
    .then(function (response) {
      showNotify("SUCCESS", "Config import requested")
    })
    .catch(function (error) {
      showNotify("ERROR", "Error during config import request")
      console.log(error);
    });
});


$("#refresh-table").click(function() {
  $("#table").bootstrapTable("refresh", {});
});


function editConfigActionsFormatter(value, row, index) {
  return [
    '<a class="task-edit-config" href="javascript:void(0)" title="Edit config">',
    '  <i class="fa fa-file-text" style="color: #858796"></i>',
    '</a>',
  ].join('')
}


window.editConfigActionsEvents = {
  "click .task-edit-config": function (e, value, row, index) {
    edit_config_row = row;
    $("#modal-edit-config").modal("show");
  }
}
