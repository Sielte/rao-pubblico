$(document).ready(function () {
        $('.it-date-datepicker').datepicker({
            inputFormat: ["dd/MM/yyyy"],
            outputFormat: 'dd/MM/yyyy',
    });
});

input_CF = document.getElementById("fiscalNumber");
input_CF.addEventListener('focusout', function () {
CF = this.value;

$.ajax({
    url: '/agency/ajax_decode_fiscal_number/',
    data: {
        'CF': CF
    },
    success: function (data) {
        if (data["statusCode"] == 200) {
            set_birth_after_form('nationOfBirth', 'countyOfBirth', 'placeOfBirth', 'Z000', data["countyOfBirth"], data["placeOfBirth"],
            date_format_change(data["dateOfBirth"]));
            document.getElementById("gender").value = data["gender"];
            $('#gender').selectpicker('refresh');
            document.getElementById('dateOfBirth').value = data["dateOfBirth"];
        }
    }
});

});

window.addEventListener('load', function () {

    document.getElementById("nationOfBirth").disabled = true;
    document.getElementById("countyOfBirth").disabled = true;
    document.getElementById("placeOfBirth").disabled = true;
    document.getElementById("dateOfBirth").disabled = true;
    document.getElementById("gender").disabled = true;

    var script_tag = document.getElementById('script_tag');
    is_form = JSON.parse(script_tag.getAttribute("data_is_form"));
    console.log("is_form vale: " + is_form);

        if(document.getElementById("typeDocRelease").value == "ministeroTrasporti") {
            document.getElementById("idCardIssuer").disabled = true;
        }
        else {
            document.getElementById("idCardIssuer").disabled = false;
        }
    is_modal_message = JSON.parse(script_tag.getAttribute("data_modal_message"));
    is_user_detail = JSON.parse(script_tag.getAttribute("data_user_detail"));

    if (is_modal_message){
        $('#modal').modal('show');
    }
    if (is_user_detail){
        $('#summary').modal('show');
    }
    var url = document.getElementById("add_identity_form").getAttribute("data-url");
    $.ajax({
        url: url,
        data: {
            'code': "",
            'select': 'nationOfBirth'
        },
        success: function (data) {
            document.getElementById("nationOfBirth").innerHTML = data;
            document.getElementById("addressNation").innerHTML = data;
            if (is_form) {

                $('#nationOfBirth').selectpicker('refresh');
                $('#addressNation').selectpicker('refresh');
                dateOfBirth_value = document.getElementById("dateOfBirth").value;
                nationOfBirth_value = script_tag.getAttribute("data_nationOfBirth_value");
                countyOfBirth_value = script_tag.getAttribute("data_countyOfBirth_value");
                placeOfBirth_value = script_tag.getAttribute("data_placeOfBirth_value");
                addressNation_value = script_tag.getAttribute("data_addressNation_value");
                addressCountry_value = script_tag.getAttribute("data_addressCountry_value");
                addressMunicipality_value = script_tag.getAttribute("data_addressMunicipality_value");

                set_birth_after_form('nationOfBirth', 'countyOfBirth', 'placeOfBirth', nationOfBirth_value,
                 countyOfBirth_value, placeOfBirth_value, date_format_change(dateOfBirth_value));

                set_birth_after_form('addressNation', 'addressCountry', 'addressMunicipality', addressNation_value, addressCountry_value, addressMunicipality_value);
            }
            else {
                $('#nationOfBirth').selectpicker('destroy');
                $('#nationOfBirth').selectpicker('render');
                $('#addressNation').selectpicker('destroy');
                $('#addressNation').selectpicker('render');
            }

        }
    });


});


function set_birth_after_form(nation, city, municipality, nation_value, city_value, municipality_value, birth_date) {

    document.getElementById(nation).value = nation_value;
    $('#' + nation).selectpicker('refresh');

    var url = document.getElementById("add_identity_form").getAttribute("data-url");
    var code = document.getElementById(nation).value;

    if (code != 'Z000') {
        toggle_disable_select(city);
        toggle_disable_select(municipality);

    } else {
        $.ajax({
            url: url,
            data: {
                'code': code,
                'select': city
            },
            success: function (data) {
                document.getElementById(city).innerHTML = data;
                $("#" + city).selectpicker('refresh');
                code = '';
                document.getElementById(city).value = city_value;
                $("#" + city).selectpicker('refresh');
                $.ajax({
                    url: url,
                    data: {
                        'code': city_value,
                        'select': municipality,
                        'birth_date': birth_date
                    },
                    success: function (data) {
                        document.getElementById(municipality).innerHTML = data;
                        $("#" + municipality).selectpicker('refresh');
                        document.getElementById(municipality).value = municipality_value;
                        $("#" + municipality).selectpicker('refresh');
                    }
                });
            }
        });
    }
}


function toggle_disable_select(select) {
    select_to_change = document.getElementById(select);
    select_to_change.disabled = !select_to_change.disabled;
    if (select_to_change.disabled) {
        document.getElementById(select + "Help").innerHTML = "Paese Estero";
        document.getElementById(select).selectedIndex = 0;
        $('#'+select).selectpicker('refresh');
    } else {
        document.getElementById(select + "Help").innerHTML = "";
    }

}

function populate_select(first_select_id, select_tochange_id) {
    select = document.getElementById(first_select_id);
    select.addEventListener("change", function () {
        var url = document.getElementById("add_identity_form").getAttribute("data-url");
        var code = this.value;
        if ((first_select_id == 'nationOfBirth' || first_select_id == 'addressNation') && code != 'Z000') {
            if (first_select_id == 'nationOfBirth') {
                county = 'countyOfBirth';
                municipality = 'placeOfBirth';
            } else {
                county = 'addressCountry';
                municipality = 'addressMunicipality';

            }
            select_to_change1 = document.getElementById(county);
            select_to_change2 = document.getElementById(municipality);
            if (!select_to_change1.disabled && !select_to_change1.disabled) {
                toggle_disable_select(county);
                toggle_disable_select(municipality);
            }

        } else {

            if (first_select_id == 'nationOfBirth') {
                select_to_change1 = document.getElementById('countyOfBirth');
                select_to_change2 = document.getElementById('placeOfBirth');
                if (!select_to_change1.disabled && !select_to_change1.disabled && code != 'Z000') {
                    toggle_disable_select('countyOfBirth');
                    toggle_disable_select('placeOfBirth');
                } else if (select_to_change1.disabled && select_to_change1.disabled && code == 'Z000') {
                    toggle_disable_select('countyOfBirth');
                    toggle_disable_select('placeOfBirth');
                }
            } else if (first_select_id == 'addressNation') {
                select_to_change1 = document.getElementById('addressCountry');
                select_to_change2 = document.getElementById('addressMunicipality');
                if (!select_to_change1.disabled && !select_to_change1.disabled && code != 'Z000') {
                    toggle_disable_select('addressCountry');
                    toggle_disable_select('addressMunicipality');
                } else if (select_to_change1.disabled && select_to_change1.disabled && code == 'Z000') {
                    toggle_disable_select('addressCountry');
                    toggle_disable_select('addressMunicipality');
                }
            }


            $.ajax({
                url: url,
                data: {
                    'code': code,
                    'select': select_tochange_id
                },
                success: function (data) {
                    document.getElementById(select_tochange_id).innerHTML = data;
                    $("#" + select_tochange_id).selectpicker('destroy');
                    $("#" + select_tochange_id).selectpicker('render');
                    if (first_select_id == "nationOfBirth") {
                        document.getElementById("placeOfBirth").innerHTML = "";
                        $('#placeOfBirth').selectpicker('destroy');
                        $('#placeOfBirth').selectpicker('render');
                    } else if (first_select_id == "addressNation") {
                        document.getElementById("addressMunicipality").innerHTML = "";
                        $('#addressMunicipality').selectpicker('destroy');
                        $('#addressMunicipality').selectpicker('render');

                    }

                }
            });

        }
    });

}


populate_select("nationOfBirth", "countyOfBirth");
populate_select("addressNation", "addressCountry");
populate_select("countyOfBirth", "placeOfBirth");
populate_select("addressCountry", "addressMunicipality");

function date_format_change(date_with_slash) {

    d = new Date(date_with_slash);
    month = '' + (d.getMonth() + 1),
    day = '' + d.getDate(),
    year = d.getFullYear();

    if (month.length < 2)
        month = '0' + month;
    if (day.length < 2)
        day = '0' + day;

    return [year, month, day].join('-');

}



function ente_change() {
    select = document.getElementById("typeDocRelease");
    select.addEventListener("change", function () {

        if(this.value == "ministeroTrasporti") {
            document.getElementById("idCardIssuer").disabled = true;
        }
        else {
            document.getElementById("idCardIssuer").disabled = false;
        }

    })

}

ente_change();


