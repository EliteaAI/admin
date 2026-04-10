// Logs

$("#modal-pylon-logs").on("show.bs.modal", function (e) {
  $("#modal-logs-pylon").text(logs_row.pylon_id);
  $("#input-logs").val("");
});


$("#btn-load").click(function() {
  axios.post(logs_api_url, {pylon_id: logs_row.pylon_id})
    .then(function (response) {
      $("#input-logs").val(response.data.logs);
    })
    .catch(function (error) {
      showNotify("ERROR", "Error during logs retrieval")
      console.log(error);
    });
});


$("#btn-enable-debug-mode").click(function() {
  axios.post(logs_api_url, {pylon_id: logs_row.pylon_id, action: "enable_debug_mode"})
    .then(function (response) {
      showNotify("SUCCESS", "Enabling debug mode requested");
    })
    .catch(function (error) {
      showNotify("ERROR", "Error during mode change");
      console.log(error);
    });
});


$("#btn-disable-debug-mode").click(function() {
  axios.post(logs_api_url, {pylon_id: logs_row.pylon_id, action: "disable_debug_mode"})
    .then(function (response) {
      showNotify("SUCCESS", "Disabling debug mode requested");
    })
    .catch(function (error) {
      showNotify("ERROR", "Error during mode change");
      console.log(error);
    });
});

$("#btn-enable-profiling").click(function() {
  axios.post(logs_api_url, {pylon_id: logs_row.pylon_id, action: "enable_profiling"})
    .then(function (response) {
      showNotify("SUCCESS", "Enabling profiling requested");
    })
    .catch(function (error) {
      showNotify("ERROR", "Error during profiling change");
      console.log(error);
    });
});


$("#btn-disable-profiling").click(function() {
  axios.post(logs_api_url, {pylon_id: logs_row.pylon_id, action: "disable_profiling"})
    .then(function (response) {
      showNotify("SUCCESS", "Disabling profiling requested");
    })
    .catch(function (error) {
      showNotify("ERROR", "Error during profiling change");
      console.log(error);
    });
});


$("#btn-enable-splash").click(function() {
  axios.post(logs_api_url, {pylon_id: logs_row.pylon_id, action: "enable_splash"})
    .then(function (response) {
      showNotify("SUCCESS", "Enabling maintenance splash requested");
    })
    .catch(function (error) {
      showNotify("ERROR", "Error during maintenance splash change");
      console.log(error);
    });
});


$("#btn-disable-splash").click(function() {
  axios.post(logs_api_url, {pylon_id: logs_row.pylon_id, action: "disable_splash"})
    .then(function (response) {
      showNotify("SUCCESS", "Disabling maintenance splash requested");
    })
    .catch(function (error) {
      showNotify("ERROR", "Error during maintenance splash change");
      console.log(error);
    });
});


// Configs

$("#modal-pylon-config").on("show.bs.modal", function (e) {
  $("#modal-config-pylon").text(config_row.pylon_id);
  $("#input-cfg-edit").val("");
});


$("#btn-cfg-load").click(function() {
  axios.get(config_api_url + "/" + config_row.pylon_id)
    .then(function (response) {
      $("#input-cfg-edit").val(response.data.config);
    })
    .catch(function (error) {
      showNotify("ERROR", "Error during config retrieval")
      console.log(error);
    });
});


$("#btn-cfg-load-raw").click(function() {
  axios.get(config_api_url + "/" + config_row.pylon_id + "?raw=true")
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
  axios.post(config_api_url + "/" + config_row.pylon_id, {action: "save", data: result})
    .then(function (response) {
      showNotify("SUCCESS", "Config save requested")
      $("#modal-pylon-config").modal("hide");
    })
    .catch(function (error) {
      showNotify("ERROR", "Error during config save")
      console.log(error);
    });
});


$("#btn-cfg-restart").click(function() {
  axios.post(config_api_url + "/" + config_row.pylon_id, {action: "restart"})
    .then(function (response) {
      showNotify("SUCCESS", "Restart requested")
      $("#modal-pylon-config").modal("hide");
    })
    .catch(function (error) {
      showNotify("ERROR", "Error during restart")
      console.log(error);
    });
});


// Splash


$("#modal-pylon-splash").on("show.bs.modal", function (e) {
  $("#modal-splash-pylon").text(splash_row.pylon_id);
  $("#input-splash-edit").val("");
});


$("#btn-splash-load").click(function() {
  axios.get(splash_api_url + "/" + splash_row.pylon_id)
    .then(function (response) {
      $("#input-splash-edit").val(response.data.splash);
    })
    .catch(function (error) {
      showNotify("ERROR", "Error during splash retrieval")
      console.log(error);
    });
});


$("#btn-splash-save").click(function() {
  var result = $("#input-splash-edit").val();
  axios.post(splash_api_url + "/" + splash_row.pylon_id, {action: "save", data: result})
    .then(function (response) {
      showNotify("SUCCESS", "Splash saved")
      $("#modal-pylon-splash").modal("hide");
    })
    .catch(function (error) {
      showNotify("ERROR", "Error during splash save")
      console.log(error);
    });
});


// Table

$("#refresh-table").click(function() {
  $("#table").bootstrapTable("refresh", {});
});


function pylonsActionsFormatter(value, row, index) {
  return [
    '<a class="task-edit-config" href="javascript:void(0)" title="Edit config">',
    '  <i class="fa fa-cog" style="color: #858796"></i>',
    '</a>',
    '&nbsp;',
    '<a class="task-show-logs" href="javascript:void(0)" title="Show logs">',
    '  <i class="fa fa-file-text" style="color: #858796"></i>',
    '</a>',
    '<a class="task-set-splash" href="javascript:void(0)" title="Set splash">',
    '  <i class="fa fa-bullhorn" style="color: #858796"></i>',
    '</a>',
  ].join('')
}


window.pylonsActionsEvents = {
  "click .task-edit-config": function (e, value, row, index) {
    config_row = row;
    $("#modal-pylon-config").modal("show");
  },
  "click .task-show-logs": function (e, value, row, index) {
    logs_row = row;
    $("#modal-pylon-logs").modal("show");
  },
  "click .task-set-splash": function (e, value, row, index) {
    splash_row = row;
    $("#modal-pylon-splash").modal("show");
  }
}
