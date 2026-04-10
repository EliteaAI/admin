$("#modal-create").on("show.bs.modal", function (e) {
  $("#form-create").get(0).reset();
});


$("#btn-save").click(function() {
  var data = $("#form-create").serializeObject();

  axios.post(api_url, data)
    .then(function (response) {
      // console.log(response);
      $("#table").bootstrapTable("refresh", {});
    })
    .catch(function (error) {
      console.log(error);
    });

  $("#modal-create").modal("hide");
});


function actionsFormatter(value, row, index) {
  return [
    '<a class="task-delete" href="javascript:void(0)" title="Delete">',
    '<i class="fa fa-trash" style="color: #858796"></i>',
    '</a>',
  ].join('')
}


window.actionsEvents = {
  "click .task-delete": function (e, value, row, index) {
    if (!window.confirm("Delete?")) {
      return;
    }
    axios.delete(api_url + "?id=" + row.id)
      .then(function (response) {
        // console.log(response);
        $("#table").bootstrapTable("remove", {
          field: "id",
          values: [row.id]
        });
      })
      .catch(function (error) {
        console.log(error);
      });
  }
}
