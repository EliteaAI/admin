$(".refresh-table-button").click(function() {
  $($(this).data("target")).bootstrapTable("refresh", {});
});


$("#btn-start-task").click(function() {
  var task = $("#task-selector").val();
  var param = $("#task-param").val();
  //
  axios.get(tasks_api_url, {params: {action: "start", scope: task + ":" + param}})
    .then(function (response) {
      if (response.data.ok) {
        showNotify("SUCCESS", "Task start requested");
        $("#table-task").bootstrapTable("refresh", {});
      } else {
        showNotify("ERROR", response.data.error);
      }
    })
    .catch(function (error) {
      showNotify("ERROR", "Error during task start request");
      console.log(error);
    });
});


$("#modal-task-logs").on("show.bs.modal", function (e) {
  $("#modal-logs-task").text(logs_row.task_id);
  $("#input-logs").val("");
  //
  window.socket.emit("task_logs_subscribe", {"tasknode_task": "id:" + logs_row.task_id});
});


$("#modal-task-logs").on("hide.bs.modal", function (e) {
  $("#modal-logs-task").text("");
  $("#input-logs").val("");
  //
  window.socket.emit("task_logs_unsubscribe", {"tasknode_task": "id:" + logs_row.task_id});
});


$(document).on("vue_init", () => {
  window.socket.on("log_data", (data) => {
    data.forEach((item) => {
      $("#input-logs").val(
        $("#input-logs").val() + item.line + "\n"
      );
    });
  });
});


function actions_formatter(value, row, index) {
  return [
    '<a class="task-show-logs" href="javascript:void(0)" title="Show logs">',
    '  <i class="fa fa-file-text" style="color: #858796"></i>',
    '</a>',
    '&nbsp;',
    '<a class="task-stop" href="javascript:void(0)" title="Stop">',
    '  <i class="fa fa-stop"></i>',
    '</a>',
  ].join('')
}


window.actions_events = {
  "click .task-stop": function (e, value, row, index) {
    axios.get(tasks_api_url, {params: {action: "stop", scope: row.task_id}})
      .then(function (response) {
        if (response.data.ok) {
          showNotify("SUCCESS", "Stop requested");
        } else {
          showNotify("ERROR", response.data.error);
        }
      })
      .catch(function (error) {
        showNotify("ERROR", "Error during stop request");
        console.log(error);
      });
  },
  "click .task-show-logs": function (e, value, row, index) {
    logs_row = row;
    $("#modal-task-logs").modal("show");
  }
}
