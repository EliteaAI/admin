// $("#modal-create").on("show.bs.modal", function (e) {
//   $("#form-create").get(0).reset();
// });


// $("#btn-save").click(function() {
//   var data = $("#form-create").serializeObject();
//
//   axios.post(api_url, data)
//     .then(function (response) {
//       // console.log(response);
//       $("#table").bootstrapTable("refresh", {});
//     })
//     .catch(function (error) {
//       console.log(error);
//     });
//
//   $("#modal-create").modal("hide");
// });


$("#btn-delete").click(function() {
  axios.delete(pylon_api_url)
    .then(function (response) {
      showNotify("SUCCESS", "Pylon restart requested")
    })
    .catch(function (error) {
      showNotify("ERROR", "Error during Pylon restart request")
      console.log(error);
    });
});


function actionsFormatter(value, row, index) {
  return [
    '<a class="task-meta" href="javascript:void(0)" title="Get metadata">',
    '<i class="fa fa-search" style="color: #858796"></i>',
    '</a>',
    '&nbsp;',
    '<a class="task-update" href="javascript:void(0)" title="Download update">',
    '<i class="fa fa-cloud-download" style="color: #858796"></i>',
    '</a>',
  ].join('')
}


window.actionsEvents = {
  "click .task-meta": function (e, value, row, index) {
    axios.get(plugin_api_url + "/" + row.name)
      .then(function (response) {
        // console.log(response);
        if (response.data.ok) {
          $("#table").bootstrapTable("updateCell", {
            index: index,
            field: "repo_version",
            value: response.data.repo_version
          });
        } else {
          showNotify("ERROR", response.data.error)
        }
      })
      .catch(function (error) {
        showNotify("ERROR", "Error during plugin metadata request")
        console.log(error);
      });
  },
  "click .task-update": function (e, value, row, index) {
    axios.put(plugin_api_url + "/" + row.name)
      .then(function (response) {
        // console.log(response);
        if (response.data.ok) {
          showNotify("SUCCESS", response.data.message)
        } else {
          showNotify("ERROR", response.data.error)
        }
      })
      .catch(function (error) {
        showNotify("ERROR", "Error during plugin update request")
        console.log(error);
      });
  }
}
