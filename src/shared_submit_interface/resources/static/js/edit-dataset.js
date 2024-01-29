function or_null (value) { return (value == "" || value == "<p><br></p>") ? null : value; }

function show_message (type, message) {
    jQuery("#message")
        .addClass(type)
        .append(message)
        .fadeIn(250);
    setTimeout(function() {
        jQuery("#message").fadeOut(500, function() {
            jQuery("#message").removeClass(type).empty();
        });
    }, 5000);
}

function gather_form_data () {
    console.log ("Gathering form data ..");
    let form_data = {
        "title":          or_null(jQuery("#title").val()),
        "affiliation":    or_null(jQuery("#affiliation").val()),
        "email":          or_null(jQuery("#email").val()),
        //"description":    or_null(jQuery("#description .ql-editor").html()),
    };

    return form_data;
}

function save_dataset (event, dataset_uuid, notify=true, on_success=jQuery.noop) {
    event.preventDefault();
    event.stopPropagation();

    form_data = gather_form_data();
    jQuery.ajax({
        url:         `/draft-dataset/${dataset_uuid}`,
        type:        "PUT",
        contentType: "application/json",
        accept:      "application/json",
        data:        JSON.stringify(form_data),
    }).done(function () {
        if (notify) {
            show_message ("success", "<p>Saved changes.</p>");
        }
        on_success ();
    }).fail(function () {
        if (notify) {
            show_message ("failure", "<p>Failed to save the draft. Please try again at a later time.</p>");
        }
    });

    console.log (`Gathered: ${JSON.stringify(form_data)}.`);
}

function activate (dataset_uuid) {
    jQuery("#save").on("click", function (event) { save_dataset (event, dataset_uuid); });
    jQuery("#transfer").on("click", function (event) { transfer_dataset (event, dataset_uuid); });
    console.log("Activated event handlers.");
}
