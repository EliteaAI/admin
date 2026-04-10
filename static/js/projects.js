const set_errors = error_data => {
    error_data?.forEach(err => {
        err.loc?.forEach(i => {
            const inpt = $(`#${i}`)
            inpt.addClass('is-invalid')
            inpt.siblings('.invalid-feedback').text(err.msg)
        })
    })
}

const clear_errors = () => {
    ['name', 'project_admin_email'].forEach(i => {
        $(`#${i}`).removeClass('is-invalid')
    })
}

const handle_update_table = () => {
    $('#projects-list').bootstrapTable('refresh')
}

async function projectCreateSubmit() {
    const submit_button = $('#project_submit')
    submit_button.attr('disabled', true)
    clear_errors()
    const api_url = V.build_api_url('projects', 'project', {trailing_slash: true})
    const project_data = {
        "name": $('#name').val(),
        "project_admin_email": $('#project_admin_email').val(),
        // "vuh_limit": 60000,
        // "plugins": V.multiselectFilter?.selectedItems.map(i => i.id) || [],
        // "storage_space_limit": 1000000000,
        "data_retention_limit": 1000000000,
        ...V.custom_data
    }
    if (document.getElementById("limit_settings").checked) {
        const limit_settings = {
            "test_duration_limit": parseInt($('#test_duration_limit').val(), 10),
            "memory_limit": parseInt($('#memory_limit').val(), 10),
            "cpu_limit": parseInt($('#cpu_limit').val(), 10),
            "vcu_hard_limit": parseInt($('#vcu_hard_limit').val(), 10),
            "vcu_soft_limit": parseInt($('#vcu_soft_limit').val(), 10),
            "vcu_limit_total_block": document.getElementById("vcu_limit_total_block_true").checked,
            "storage_hard_limit": parseInt($('#storage_hard_limit').val(), 10),
            "storage_soft_limit": parseInt($('#storage_soft_limit').val(), 10),
            "storage_limit_total_block": document.getElementById("storage_limit_total_block_true").checked,
        }
        Object.assign(project_data, limit_settings);
    }
    try {
        const resp = await fetch(api_url, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(project_data)
        })
        if (resp.ok) {
            $("#projectCreateModal").modal('hide');
            const data = await resp.json()
            const newSections = data['plugins']
            const currentSection = "admin"
            const notAdmin = !V.navbar.isAdmin

            if (notAdmin && !newSections?.includes(currentSection) && newSections?.length > 0) {
                const section = newSections[0]
                location.href = window.url_prefix + `/-/${section}`
                $('select.selectpicker[name="section_select"]').val(section)
            } else {
                handle_update_table()
                showNotify('SUCCESS', 'Project created')
            }
        } else {
            const err_data = await resp.json()
            set_errors(err_data)
        }
    } catch (e) {
        console.error(e)
        showNotify('ERROR', 'Error creating project')
    } finally {
        submit_button.attr('disabled', false)
    }


}

const handle_delete_project = async (project_id) => {
    const api_url = V.build_api_url('projects', 'project', {trailing_slash: true})
    const resp = await fetch(api_url + project_id, {
        method: 'DELETE'
    })
    if (resp.ok) {
        handle_update_table()
        showNotify('SUCCESS', 'Project deleted')
    } else {
        const err_data = await resp.json()
        console.error(err_data)
    }
}

function projectActionFormatter(value, row, index) {
    const delete_btn = `
        <button
            class="btn btn-default btn-xs btn-table btn-icon__xs ml-1"
            onclick="handle_delete_project(${row.id})"
        ><i class="icon__18x18 icon-delete"></i></button>
    `
    return '<div class="d-flex justify-content-end">' +
        '<a href="' + window.url_prefix + '/~/administration/~/projects/list/edit?project=' + row.id + '" class="btn btn-default btn-xs btn-table btn-icon__xs"><i class="fas fa-sync"></i></a>'
        + delete_btn + '</div>'

}

$(document).on('vue_init', () => {
    $('#project_submit').on('click', projectCreateSubmit)

    $("#userInviteModal").on("show.bs.modal", function (e) {
      $("#user_name").val("");
      $("#user_email").val("");
    });

    $("#invite_submit").click(function() {
      var user_name = $("#user_name").val();
      var user_email = $("#user_email").val();
      //
      axios.post(user_invite_url, {user_name: user_name, user_email: user_email})
        .then(function (response) {
          if (response.data.ok) {
            showNotify("SUCCESS", "User invite requested");
            $("#userInviteModal").modal("hide");
          } else {
            showNotify("ERROR", response.data.error);
          }
        })
        .catch(function (error) {
          showNotify("ERROR", "Error during invite request");
          console.log(error);
        });
    });
})
