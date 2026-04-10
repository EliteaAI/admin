const RolesModalCreate = {
    props: ['editableRoles', 'modalType'],
    data() {
        return {
            newRoleName: '',
            saveClicked: false,
        }
    },
    computed: {
        isNameYetExist() {
            return this.editableRoles.includes(this.newRoleName);
        },
        hasError() {
            return this.newRoleName.length < 3 && this.saveClicked;
        },
    },
    methods: {
        handleSubmit() {
            this.saveClicked = true;
            if (this.isNameYetExist) {
                showNotify('ERROR', 'The same name is exist');
                return
            }
            if (this.hasError) return;
            switch (this.modalType) {
                case 'create':
                    this.$emit('save-column', this.newRoleName);
                    break;
                case 'edit':
                    this.$emit('update-column', this.newRoleName);
                    break;
            }
        },
    },
    template: `
    <div class="modal-component">
        <div class="modal-card">
            <p class="font-bold font-h3 mb-4 text-capitalize">{{ modalType }} role</p>
            <div class="custom-input need-validation mb-4 w-100" :class="{'invalid-input': hasError}">
                <label for="BucketName" class="font-semibold font-h4 mb-1">Name</label>
                <input
                    id="roleName"
                    type="text"
                    v-model="newRoleName"
                    placeholder="Role name">
                <span class="input_error-msg">Role's name less than 3 letters</span>
            </div>
            <div class="d-flex justify-content-end">
                <button type="button" class="btn btn-secondary mr-2" @click="$emit('close-create-modal')">Cencel</button>
                <button
                    class="btn btn-basic mr-2 d-flex align-items-center"
                    @click="handleSubmit"
                >Save</button>
            </div>
        </div>
    </div>
`
}