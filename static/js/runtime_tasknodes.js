$(".refresh-table-button").click(function() {
  $($(this).data("target")).bootstrapTable("refresh", {});
});


$(".refresh-pool-button").click(function() {
  var target = $(this).data("target");
  //
  axios.get(tasknodes_api_url, {params: {action: "refresh", node: $(this).data("node"), scope: "pool"}})
    .then(function (response) {
      if (response.data.ok) {
        showNotify("SUCCESS", "Refresh request completed");
        $(target).bootstrapTable("refresh", {});
      } else {
        showNotify("ERROR", response.data.error);
      }
    })
    .catch(function (error) {
      showNotify("ERROR", "Error during refresh request");
      console.log(error);
    });
});


$(".refresh-task-button").click(function() {
  var target = $(this).data("target");
  //
  axios.get(tasknodes_api_url, {params: {action: "refresh", node: $(this).data("node"), scope: "task"}})
    .then(function (response) {
      if (response.data.ok) {
        showNotify("SUCCESS", "Refresh request completed");
        $(target).bootstrapTable("refresh", {});
      } else {
        showNotify("ERROR", response.data.error);
      }
    })
    .catch(function (error) {
      showNotify("ERROR", "Error during refresh request");
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
    axios.get(tasknodes_api_url, {params: {action: "stop", node: row.node, scope: row.task_id}})
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
