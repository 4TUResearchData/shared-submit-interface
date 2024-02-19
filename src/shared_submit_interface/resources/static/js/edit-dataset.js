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
    let form_data = {
        "title":          or_null(jQuery("#title").val()),
        "affiliation":    or_null(jQuery("#affiliation-uuid").val()),
        "domain":         or_null(jQuery("#research-domain").val()),
        "datatype":       or_null(jQuery("#type-of-data").val()),
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
        url:         `/api/v1/dataset/${dataset_uuid}`,
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
}

function set_organization (event, dataset_uuid) {
    let values = jQuery("input[name='organization']:checked").val().split(":");
    let uuid = values[0];
    let name = values[1];
    jQuery("#affiliation-uuid").val(uuid);
    jQuery("#affiliation").val(name);
    jQuery("#affiliation-ac").remove();
    jQuery("#affiliation").removeClass("input-for-ac");
    jQuery("#email").focus();
}
function autocomplete_organization (event, dataset_uuid) {
    if (event !== null) {
        event.preventDefault();
        event.stopPropagation();
    }

    let current_text = jQuery.trim(jQuery("#affiliation").val());
    if (current_text == "") {
        jQuery("#affiliation-ac").remove();
        jQuery("#affiliation").removeClass("input-for-ac");
        jQuery("#affiliation-uuid").val("");
    } else if (current_text.length > 2) {
        jQuery.ajax({
            url:         `/api/v1/organizations`,
            type:        "POST",
            contentType: "application/json",
            accept:      "application/json",
            data:        JSON.stringify({ "search_for": current_text }),
            dataType:    "json"
        }).done(function (data) {
            jQuery("#affiliation-ac").remove();
            let html = '<ul id="affiliation-list">';
            if (data.length == 0) {
                html += "<li>No affiliated organization found.";
            }
            for (let item of data) {
                html += `<li><input type="radio" id="organization-${item['uuid']}" `;
                html += `name="organization" value="${item['uuid']}:${item['name']}">`;
                html += `<label class="no-head" for="organization-${item['uuid']}">${item['name']}</label>`;
            }
            html += "</ul>";
            jQuery("#affiliation")
                .addClass("input-for-ac")
                .after(`<div id="affiliation-ac" class="autocomplete">${html}</div>`);
            jQuery("#affiliation-list").on("change", function (event) { return set_organization (event, dataset_uuid); });
        });
    }
}

function activate (dataset_uuid) {
    jQuery("#save").on("click", function (event) { save_dataset (event, dataset_uuid); });
    jQuery("#transfer").on("click", function (event) { transfer_dataset (event, dataset_uuid); });
    jQuery("#affiliation").on("input", function (event) { autocomplete_organization (event, dataset_uuid); });
}
