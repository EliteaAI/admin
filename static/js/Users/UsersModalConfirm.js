const UsersModalConfirm = {
    props: ['loadingDelete'],
    template: `
    <div class="modal-component" @click.self="$emit('close-confirm')">
        <div class="modal-card">
            <p class="font-bold font-h3 mb-4">Delete users?</p>
            <p class="font-h4 mb-4">Are you sure to delete users?</p>
            <div class="d-flex justify-content-end mt-4">
                <button type="button" class="btn btn-secondary mr-2" @click="$emit('close-confirm')">Cencel</button>
                <button
                    class="btn btn-basic d-flex align-items-center"
                    @click="$emit('delete')"
                >Delete<i class="preview-loader__white ml-1" v-if="loadingDelete"></i></button>
            </div>
        </div>
    </div>
`
}