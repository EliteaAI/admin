const EmptyPage = {
    props: ['user_projects', 'logo_url'],
    delimiters: ['[[', ']]'],
    data() {
        return {
            selected_project: null,
        }
    },
    methods: {
        async handle_project_change(event) {
            await activeProject.set(this.selected_project)
            window.location.href = window.url_prefix + '/-/configuration/artifacts/'
        }
    },
    template: `
        <div class="full-screen center">
            <div class="welcome-card">
                <div class="welcome-card-header">
                    <img :src="logo_url" alt="logo"/>
                </div>
                <div class="welcome-card-body">
                    <h3>Welcome back!</h3>
                    <p>Select the project to continue</p>
                    <div class="d-flex w-100">
                        <select v-model="selected_project"
                            class="selectpicker bootstrap-select__b flex-grow-1 mr-2"
                            data-style="btn"
                            data-placeholder="Select project"
                            >
                            <option value="" selected disabled hidden>Select project</option>
                            <option v-for="project in user_projects"
                                :value="project.id"
                                :key="project.id"
                                >
                                [[ project.name ]]
                            </option>
                        </select>
                        <button class="btn btn-basic btn-lg mr-2" @click="handle_project_change">Go!</button>
                    </div>
                </div>
            </div>
        </div>
       `,
}

register_component('empty-page', EmptyPage);
